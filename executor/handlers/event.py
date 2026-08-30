# Copyright 2025 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
import time
import redis
import requests

import cachetools.func

from pottery import Redlock
from json import dumps as json_dump
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from msgpack import dumps as msgpack_dump, loads as msgpack_load
from sqlalchemy.dialects.postgresql import insert as pg_insert
from celery.utils.log import get_task_logger
from celery.signals import worker_ready
from sqlalchemy import and_, select, tuple_, literal, update, func, cast, case, BigInteger, Float
from ..models import (
    User,
    Model,
    Script,
    ScriptVersion,
    Group,
    Config,
    UserScript,
    Activity,
    ActivityCategory,
    ActivitySeverity,
    DeviceStatus,
    Device,
    UserDevice,
    DeviceJob,
    Task,
    Job,
    TaskResource,
    ModelResource,
    DeviceState,
    DeviceMode,
    DeviceJobState,
    DeviceJobTaskState,
    DeviceJobBindingState,
    TaskState,
    TaskResourceType,
    JobMode,
    JobState,
    ParamSource,
    Session,
    session_scope,
    Base,
    engine,
)
from ..utils import (
    r_task_id,
    certdir,
    get_public_ip_info,
    save_cert,
    remove_cert,
    r_string,
)

from ..config import db, lockers
from ..queue import pop_next_event, queue_pop_fallback, queues_delete
from ..celery import app

logger = get_task_logger(__name__)


def send_event(topic, data):
    payload = json_dump(dict(topic=topic, data=json_dump(data)))
    return db.lpush("mqtt/event", payload)


def send_node_command(command, data, *ids, correlation_id=None):
    messages = [msgpack_dump(dict(id=id, command=command, correlation_id=correlation_id,
                                                                        data=data)) \
                                            for id in ids]
    return db.lpush("mqtt/command", *messages)


def reset_devicejob_state(session, dt):
    dt.state = DeviceJobState.INITIAL.value
    dt.task_state = DeviceJobTaskState.INITIAL.value
    dt.last_state_update_time = 0
    session.flush()


def weighted_selection(dts_with_weights):
    func = lambda t: float(getattr(t[0], "credit", 0) or 0)
    return max(dts_with_weights, key=func)[0]


def weighted_issue_iter(dts, dispatch):
    candidates = list(dts)
    for dt in candidates:
        dt.credit = float(dt.credit or 0) + (max(int(
                                    dt.job.priority or 1), 1) / 100.0)
    while candidates:
        dt = weighted_selection([(t, t.job.priority) for t in candidates])
        candidates.remove(dt)
        if dispatch(dt) == True:
            dt.credit = float(dt.credit or 0) - 0.01
            return True


def create_device_activity(session, d, action, severity, meta=None):
    activity = dict()
    activity["action"] = action
    activity["device_id"] = d.id
    activity["category"] = ActivityCategory.DEVICE.value
    activity["severity"] = severity
    activity["meta"] = meta or {}
    session.add(Activity(**activity))
    session.flush()


def ensure_devicejob_records_batch(session):
    stmt = pg_insert(DeviceJob).from_select([
                DeviceJob.device_id,
                DeviceJob.job_id,
                DeviceJob.state,
                DeviceJob.last_state_update_time,
                DeviceJob.task_state,
                DeviceJob.binding_state,
                DeviceJob.issued,
                DeviceJob.credit,
                DeviceJob.last_issue_time,
                DeviceJob.success,
                DeviceJob.failed,
                DeviceJob.timeout,
                DeviceJob.revoked,
                DeviceJob.create_time,
                DeviceJob.leave_time,
        ],
        select(
                UserDevice.device_id,
                Job.id,
                literal(DeviceJobState.INITIAL.value),
                literal(0),
                literal(DeviceJobTaskState.IDLE.value),
                literal(DeviceJobBindingState.ACTIVE.value),
                literal(0),
                literal(0.0),
                literal(0),
                literal(0),
                literal(0),
                literal(0),
                literal(0),
                literal(time.time()),
                literal(0),
        ).select_from(Job).join(UserDevice, and_(
                UserDevice.user_id == Job.owner_id,
                UserDevice.group_id == Job.group_id,
        )).join(Device, Device.id == UserDevice.device_id).filter(
                Device.state == DeviceState.ONLINE.value,
                Device.is_deleted == False,
                Job.group_id.is_not(None),
                Job.state == JobState.RUNNING.value,
        ).group_by(UserDevice.device_id, Job.id)
    ).on_conflict_do_nothing(index_elements=[
            DeviceJob.device_id,
            DeviceJob.job_id,
    ])
    session.execute(stmt)
    session.flush()


def sync_devicejob_binding_batch(session):
    active_pairs = select(
            UserDevice.device_id,
            Job.id,
    ).select_from(Job).join(UserDevice, and_(
            UserDevice.user_id == Job.owner_id,
            UserDevice.group_id == Job.group_id,
    )).join(Device, Device.id == UserDevice.device_id).filter(
            Device.state == DeviceState.ONLINE.value,
            Device.is_deleted == False,
            Job.group_id.is_not(None),
            Job.state.in_([JobState.RUNNING.value, JobState.PAUSED.value]),
    )
    online_device_ids = select(Device.id).filter(
            Device.state == DeviceState.ONLINE.value,
            Device.is_deleted == False,
    )
    managed_job_ids = select(Job.id).filter(
            Job.state.in_([JobState.RUNNING.value, JobState.PAUSED.value]),
    )
    session.query(DeviceJob).filter(
            DeviceJob.device_id.in_(online_device_ids),
            tuple_(DeviceJob.device_id, DeviceJob.job_id).in_(active_pairs),
    ).update(dict(
            binding_state=DeviceJobBindingState.ACTIVE.value,
            leave_time=0,
    ), synchronize_session=False)
    session.query(DeviceJob).filter(
            DeviceJob.device_id.in_(online_device_ids),
            DeviceJob.job_id.in_(managed_job_ids),
            ~tuple_(DeviceJob.device_id, DeviceJob.job_id).in_(active_pairs),
            DeviceJob.binding_state != DeviceJobBindingState.REMOVED.value,
    ).update(dict(
            binding_state=DeviceJobBindingState.REMOVED.value,
            leave_time=time.time(),
    ), synchronize_session=False)


def sync_devicejob_binding_by_device(session, device):
    active_job_ids = session.query(Job.id).join(UserDevice, and_(
            UserDevice.user_id == Job.owner_id,
            UserDevice.group_id == Job.group_id)
    ).filter(UserDevice.device_id == device.id,
            Job.group_id.is_not(None),
            Job.state.in_([JobState.RUNNING.value, JobState.PAUSED.value]))
    managed_job_ids = session.query(Job.id).filter(
            Job.state.in_([JobState.RUNNING.value, JobState.PAUSED.value]))
    session.query(DeviceJob).filter(
            DeviceJob.device_id == device.id,
            DeviceJob.job_id.in_(active_job_ids)
    ).update(dict(binding_state=DeviceJobBindingState.ACTIVE.value,
            leave_time=0), synchronize_session=False)
    session.query(DeviceJob).filter(
            DeviceJob.device_id == device.id,
            DeviceJob.job_id.in_(managed_job_ids),
            ~DeviceJob.job_id.in_(active_job_ids),
            DeviceJob.binding_state != DeviceJobBindingState.REMOVED.value
    ).update(dict(binding_state=DeviceJobBindingState.REMOVED.value,
        leave_time=time.time()), synchronize_session=False)


def ensure_devicejob_records_by_device(session, device):
    stmt = pg_insert(DeviceJob).from_select([
                DeviceJob.device_id,
                DeviceJob.job_id,
                DeviceJob.state,
                DeviceJob.last_state_update_time,
                DeviceJob.task_state,
                DeviceJob.binding_state,
                DeviceJob.issued,
                DeviceJob.credit,
                DeviceJob.last_issue_time,
                DeviceJob.success,
                DeviceJob.failed,
                DeviceJob.timeout,
                DeviceJob.revoked,
                DeviceJob.create_time,
                DeviceJob.leave_time,
        ],
        select(
                literal(device.id),
                Job.id,
                literal(DeviceJobState.INITIAL.value),
                literal(0),
                literal(DeviceJobTaskState.IDLE.value),
                literal(DeviceJobBindingState.ACTIVE.value),
                literal(0),
                literal(0.0),
                literal(0),
                literal(0),
                literal(0),
                literal(0),
                literal(0),
                literal(time.time()),
                literal(0),
        ).select_from(Job).join(UserDevice, and_(
                UserDevice.user_id == Job.owner_id,
                UserDevice.group_id == Job.group_id,
        )).filter(
                UserDevice.device_id == device.id,
                Job.group_id.is_not(None),
                Job.state == JobState.RUNNING.value,
        ).group_by(Job.id)
    ).on_conflict_do_nothing(index_elements=[
                DeviceJob.device_id,
                DeviceJob.job_id,
    ])
    session.execute(stmt)
    session.flush()


def mark_lost_tasks_batch(session):
    now = int(time.time())
    raw_limit = cast(func.json_extract_path_text(Job.config,
                                      "time_limit"), Float)
    session.execute(update(Task).where(
            Task.job_id == Job.id,
Task.state.in_([TaskState.PENDING.value, TaskState.ISSUED.value,
                                            TaskState.RUNNING.value]),
Task.create_time <= literal(now) - cast(case(
                    (raw_limit <= 0, 86400.0),
                    else_=func.coalesce(raw_limit, 86400.0),
            ) * 1.5, BigInteger),
    ).values(
            state = TaskState.LOST.value,
            finish_time = now))


def get_eligible_devicejobs(session, device):
    running_jobs = session.query(Job).join(UserDevice, and_(
                    UserDevice.user_id == Job.owner_id,
                    UserDevice.group_id == Job.group_id)
    ).filter(
                    UserDevice.device_id == device.id,
                    Job.group_id.is_not(None),
                    Job.state == JobState.RUNNING.value,
                    Job.mode != JobMode.CRONTAB.value,
    ).group_by(Job.id).all()
    running_job_ids = [job.id for job in running_jobs]

    return list(session.query(DeviceJob).join(Job).filter(
                    DeviceJob.device_id == device.id,
                    DeviceJob.binding_state == DeviceJobBindingState.ACTIVE.value,
                    DeviceJob.job_id.in_(running_job_ids)
    ))


def is_device_in_job_group(session, device, job):
    if not job.group_id: return False
    return session.query(UserDevice.id).filter(
    UserDevice.device_id == device.id, UserDevice.user_id == job.owner_id,
    UserDevice.group_id == job.group_id).first() is not None


def update_devicejob_binding_state(session, dt, bind):
    state, t = (    (DeviceJobBindingState.REMOVED.value, time.time()),
                    (DeviceJobBindingState.ACTIVE.value, 0))[bind]
    if dt.binding_state == state: return None
    dt.binding_state = state
    dt.leave_time = t
    session.flush()


def increase_devicejob_revoked(session, task_id):
    session.query(DeviceJob).filter(
            DeviceJob.job_id == Task.job_id,
            DeviceJob.device_id == Task.device_id,
            Task.task_id == task_id,
            Task.finish_time == 0,
    ).update(
            {DeviceJob.revoked: DeviceJob.revoked + 1},
            synchronize_session=False,
    )


def set_gateway(d, host, port,
                                ttl=10*60):
    rule = f"{host}:{port},{d.auth_token}"
    db.setex(f"gw:{d.domain}", int(ttl),
                                rule)


def host_from_mode(d):
    mode = dict()
    mode[DeviceMode.DIRECT.value] = lambda d: d.default_ip
    mode[DeviceMode.FORWARD.value] = lambda d: "127.0.0.1"
    mode[DeviceMode.P2P.value] = lambda d: d.top_ip
    return mode[d.mode](d)


def update_public_ip_info(d, ip):
    info = get_public_ip_info(ip)
    d.public_ip = ip
    d.ip_lat    = info.get("latitude", 0)
    d.ip_lng    = info.get("longitude", 0)
    d.ip_country= info.get("country_long")
    d.ip_region = info.get("region")
    d.ip_city   = info.get("city")


def assemble_script(job):
    s = job.script
    meta = dict()
    meta["name"] = s.parent.name
    meta["description"] = s.parent.description
    conf = dict()
    conf["name"] = "v%s%s.%s" % (s.parent.id, s.id,
                                    s.parent.entry["method"])
    conf.update(job.config)
    code = []
    code.append(f"{s.code}")
    m = job.model
    agent = f'AnyLLMUiautomatorAgent("{m.api_base}", "{m.api_key}", "{m.model_name}", provider="{m.provider}", vision={m.vision_mode}, scale={m.vision_scale}, temperature={m.temperature}, max_completion_tokens={m.max_completion_tokens}, context_window={m.context_window}, step_delay={m.step_delay})' if m else 'None'
    code.append(f"FireRPATaskExecutor.agent  = {agent}")
    code.append(f"FireRPATaskExecutor.config = {conf}")
    code.append(f"FireRPATaskExecutor.config[\"base\"] = globals().get(\"FireRPABaseTaskExecutor\")")
    code.append(f"FireRPATaskExecutor.metadata = {meta}")
    return "\n".join(code)


@app.task
def stop(session, job, with_running=False,
                                    revoke=True):
    queues_delete(f"job:{job.id}:*")
    session.query(Job).filter(Job.id==job.id).update(dict(
            stop_time=time.time(),
            state=JobState.STOPPED.value
                                            ), synchronize_session=False)
    session.flush()
    if revoke != True:
        return
    execution_states = [TaskState.PENDING.value,
                                                TaskState.ISSUED.value]
    if with_running:
        execution_states.append(TaskState.RUNNING.value)
    rows = session.query(Device.dev_id, Task.task_id).join(Device, Task.device_id == Device.id).filter(
                Task.job_id == job.id,
                Device.dev_id.is_not(None),
                Task.state.in_(execution_states)
            ).all()
    mapping = {}
    for dev_id, task_id in rows:
        mapping.setdefault(dev_id, []).append(task_id)
    if len(mapping):
        for dev_id, ids in mapping.items():
            send_node_command("task/revoke", dict(task_id=ids),
                                dev_id)


def lock_job(session, job_id):
    session.execute(
        select(Job.id).where(Job.id == job_id).with_for_update()
    ).first()


@app.task
def expire():
    with session_scope() as session:
        deadline = (time.time() - 3.0*60)
        session.query(Device).filter(Device.last_heartbeat_time < deadline,
                                     Device.state != DeviceState.PENDING.value).update(
                                        dict(state=DeviceState.OFFLINE.value), synchronize_session=False)


def event_handle_PING(session, data):
    return None


def event_handle_HELO(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    prev = d.state
    info = data["data"]
    d.dev_id        = data["device_id"]
    d.serialno      = data.get("serialno", None)
    d.privileged    = data.get("privileged", True)
    d.board         = info["board"]
    d.hardware      = info["hardware"]
    d.brand         = info["brand"]
    d.device        = info["device"]
    d.model         = info["model"]
    d.abi           = info["abi"]
    d.sdk           = info["sdk"]
    d.boot_time     = info["uptime"]
    d.version       = info["version"]
    d.state         = DeviceState.ONLINE.value
    d.last_heartbeat_time = data["received"]
    session.query(DeviceJob).filter(DeviceJob.device_id==d.id).update(
                                        dict(state=DeviceJobState.INITIAL.value, task_state=DeviceJobTaskState.IDLE.value), synchronize_session=False)
    session.flush()
    if prev != DeviceState.ONLINE.value:
        create_device_activity(session, d, "device.online", ActivitySeverity.SUCCESS.value,
                                                        dict(domain=d.domain))


def event_handle_BYE(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    prev = d.state
    d.controlling_cid = None
    d.controlling = False
    d.state       = DeviceState.OFFLINE.value
    d.frida_token       = None
    d.lock_token        = None
    d.batt_charging = False
    d.api_available = False
    d.locked      = False
    db.delete(f"gw:{d.domain}")
    session.flush()
    if prev != DeviceState.OFFLINE.value:
        create_device_activity(session, d, "device.offline", ActivitySeverity.WARNING.value,
                                                        dict(domain=d.domain))


def event_handle_CLOUD_HELO(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    info = data["data"]
    d.top_ip        = info["top_ip"]
    d.vpn_ip        = info["vpn_ip"]
    d.default_ip    = info["default_ip"]
    d.service_port  = (d.service_port, info["service_port"])[d.mode!=DeviceMode.FORWARD.value]
    update_public_ip_info(d, info.get("public_ip"))
    d.locked        = info["locked"]
    d.api_available = info["api_available"]
    d.frida_token         = info["frida"]
    d.lock_token          = info["lock"]
    d.controlling   = bool(info["controlling"])
    d.controlling_cid = info["controlling"]
    host = host_from_mode(d)
    set_gateway(d, host, d.service_port)
    save_cert(certdir, d.domain, d.cert)
    session.flush()


def event_handle_CONTROL_ENTER(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    info = data["data"]
    d.controlling = True
    d.controlling_cid = info["client"]
    session.flush()


def event_handle_CONTROL_LEAVE(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    d.controlling = False
    d.controlling_cid = None
    session.flush()


def event_handle_LOCK(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    info = data["data"]
    d.frida_token         = info["frida"]
    d.lock_token          = info["lock"]
    d.locked        = True
    session.flush()


def event_handle_UNLOCK(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    d.lock_token          = None
    d.locked        = False
    session.flush()


def event_handle_DEVICE_STATUS(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    info = data["data"]
    d.last_heartbeat_time = data["received"]
    d.top_ip        = info["top_ip"]
    d.vpn_ip        = info["vpn_ip"]
    d.default_ip    = info["default_ip"]
    update_public_ip_info(d, info.get("public_ip"))
    d.service_port  = (d.service_port, info["service_port"])[d.mode!=DeviceMode.FORWARD.value]
    d.disk_used     = info["disk_used"]
    d.disk_percent  = info["disk_percent"]
    d.batt_percent  = info["batt_percent"]
    d.mem_used      = info["mem_used"]
    d.mem_percent   = info["mem_percent"]
    d.mem_total     = info["mem_total"]
    d.disk_total    = info["disk_total"]
    d.cpu_count     = info["cpu_count"]
    d.batt_charging = info["batt_charging"]
    d.api_available = info["api_available"]
    d.state         = DeviceState.ONLINE.value
    d.locked        = info["locked"]
    session.flush()
    host = host_from_mode(d)
    set_gateway(d, host, d.service_port)
    ds = dict()
    ds["batt_percent"] = info["batt_percent"]
    ds["batt_temperature"] = info["batt_temperature"]
    ds["core_temperature"] = info.get("core_temperature", 0)
    ds["cpu_freq_current"] = info["cpu_freq_current"]
    ds["cpu_freq_max"] = info["cpu_freq_max"]
    ds["cpu_freq_min"] = info["cpu_freq_min"]
    ds["cpu_percent"] = info["cpu_percent"]
    ds["cpu_times_idle"] = info["cpu_times_idle"]
    ds["cpu_times_system"] = info["cpu_times_system"]
    ds["cpu_times_user"] = info["cpu_times_user"]
    ds["crash_count"] = info["crash_count"]
    ds["disk_free"] = info["disk_free"]
    ds["disk_io_busy_time"] = info.get("disk_io_busy_time", 0)
    ds["disk_io_read_bytes"] = info.get("disk_io_read_bytes", 0)
    ds["disk_io_read_count"] = info.get("disk_io_read_count", 0)
    ds["disk_io_read_time"] = info.get("disk_io_read_time", 0)
    ds["disk_io_write_bytes"] = info.get("disk_io_write_bytes", 0)
    ds["disk_io_write_count"] = info.get("disk_io_write_count", 0)
    ds["disk_io_write_time"] = info.get("disk_io_write_time", 0)
    ds["disk_percent"] = info["disk_percent"]
    ds["disk_used"] = info["disk_used"]
    ds["fd_count"] = info["fd_count"]
    ds["mem_active"] = info["mem_active"]
    ds["mem_available"] = info["mem_available"]
    ds["mem_buffers"] = info["mem_buffers"]
    ds["mem_cached"] = info["mem_cached"]
    ds["mem_free"] = info["mem_free"]
    ds["mem_inactive"] = info["mem_inactive"]
    ds["mem_percent"] = info["mem_percent"]
    ds["mem_shared"] = info["mem_shared"]
    ds["mem_slab"] = info["mem_slab"]
    ds["mem_used"] = info["mem_used"]
    ds["net_io_bytes_recv"] = info["net_io_bytes_recv"]
    ds["net_io_bytes_sent"] = info["net_io_bytes_sent"]
    ds["net_io_packets_recv"] = info["net_io_packets_recv"]
    ds["net_io_packets_sent"] = info["net_io_packets_sent"]
    ds["process_count"] = info["process_count"]
    ds["tcpcon_count"] = info["tcpcon_count"]
    ds["thread_count"] = info["thread_count"]
    ds["udpcon_count"] = info["udpcon_count"]
    ds["wlan_freq"] = info["wlan_freq"]
    ds["wlan_linkspeed"] = info["wlan_linkspeed"]
    ds["wlan_rssi"] = info["wlan_rssi"]
    r = DeviceStatus(device_id=d.id, **ds)
    session.add(r)
    session.flush()


def event_handle_TASK_LIST(session, data):
    logger.debug("TASK_LIST event: %s", data)


def cb_task_status_initial(session, dt):
    module = f"job_{dt.job.id}"
    code = assemble_script(dt.job)
    dt.state = DeviceJobState.SCRIPT_ISSUED.value
    dt.last_state_update_time = time.time()
    session.flush()
    send_node_command("task/load", dict(module=module, code=code),
                                                   dt.device.dev_id,
                                    correlation_id=dt.job.id)


def cb_task_status_script_issued(session, dt):
    if time.time() - dt.last_state_update_time > 25:
        reset_devicejob_state(session, dt)


def cb_task_status_script_accepted(session, dt):
    if time.time() - dt.last_state_update_time > 25:
        reset_devicejob_state(session, dt)


def cb_task_status_script_load_failed(session, dt):
    if time.time() - dt.last_state_update_time > 45:
        reset_devicejob_state(session, dt)


def cb_task_params_native(task_id, dt):
    return None, dt.job.params


def cb_task_params_callback(task_id, dt):
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=[500, 502, 503, 504, 100])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    queries = dict()
    queries["device"] = dt.device.domain
    queries["domain"] = dt.device.domain
    queries["job_id"] = dt.job.id
    queries["job_name"] = dt.job.name
    queries["task_id"] = task_id
    extras = dict()
    extras["url"] = dt.job.params["url"]
    extras["headers"] = dt.job.params.get("headers", {})
    extras["timeout"] = (15, 60)
    res = s.request(method="GET", params=queries, verify=False,
                                            **extras)
    logger.warning("task params: %s %s" % (extras["url"],
                                     res.text))
    if res.status_code != 200:
        return None, None
    task = res.json()
    return task.get("task_id"), task.get("params")


def cb_task_params_queue(task_id, dt):
    domain = dt.device.domain
    data = queue_pop_fallback(f"job:{dt.job.id}:{domain}",
                                    f"job:{dt.job.id}:")
    if not data:
        return None, None
    task = msgpack_load(data)
    return task.get("task_id"), task.get("params")


def report_task_result_native(dt, se):
    return None


def task_result_to_dict(se):
    return se.to_dict(only=("id",
                            "task_id",
                            "params",
                            "state",
                            "result",
                            "reason",
                            "exception",
                            "traceback",
                            "elapsed_time",
                            "start_time",
                            "finish_time",
                            "create_time"))


def build_task_result_payload(dt, se):
    callback = dt.job.params.get("callback")
    if callback == None:
        return None
    queries = dict()
    queries["device"] = dt.device.domain
    queries["domain"] = dt.device.domain
    queries["job_id"] = dt.job.id
    queries["job_name"] = dt.job.name
    queries["task_id"] = se.task_id
    payload = dict()
    payload["url"] = callback
    payload["headers"] = dt.job.params.get("headers", {})
    payload["timeout"] = (15, 60)
    payload["params"] = queries
    payload["json"] = task_result_to_dict(se)
    return payload


@app.task(bind=True)
def report_task_result_http(self, payload):
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=[500, 502, 503, 504, 100])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    res = s.request(method="POST", verify=False, **payload)
    logger.warning("upload result: %s %s" % (payload["url"],
                                             res.text))
    return None


def report_task_result_callback(dt, se):
    payload = build_task_result_payload(dt, se)
    if payload == None:
        return None
    report_task_result_http.apply_async((payload,),
                                                  ignore_result=True,
                                                  countdown=0)


def report_task_result_queue(dt, se):
    data = task_result_to_dict(se)
    # publish to notify sync api
    db.publish(f"job:result:{se.task_id}",
                    msgpack_dump(data))
    report_task_result_callback(dt, se)


def report_task_result(dt, se):
    source = dt.job.param_source
    func = globals().get(f"report_task_result_{source}")
    return func(dt, se)


def cb_task_status_prepared_imp(session, dt):
    if dt.job.state != JobState.RUNNING.value:
        return None
    if not is_device_in_job_group(session, dt.device, dt.job):
        return update_devicejob_binding_state(session, dt, False)
    if abs(time.time() - (dt.last_issue_time or time.time())) \
                            < (dt.cooldown or dt.job.interval):
        return None
    if time.time() - dt.last_state_update_time >= dt.job.config.get("time_limit", 0) \
                                                        + dt.job.interval:
        dt.task_state = DeviceJobTaskState.IDLE.value
    if dt.device.state != DeviceState.ONLINE.value:
        return None
    if dt.task_state != DeviceJobTaskState.IDLE.value:
        return None
    funcs = dict()
    funcs[JobMode.LOOP.value]  = lambda dt: (False, True)
    funcs[JobMode.COUNT.value] = lambda dt: (dt.job.issued >= dt.job.count, True)
    funcs[JobMode.PER_DEVICE_COUNT.value] = lambda dt: (session.query(DeviceJob.id).filter(DeviceJob.job_id==dt.job_id, DeviceJob.issued < dt.job.count).first() is None, dt.issued < dt.job.count)
    funcs[JobMode.DEADLINE.value]  = lambda dt: (dt.job.count >= time.time(), True)
    funcs[JobMode.CRONTAB.value] = lambda dt: (False, True)
    finish, issue = funcs[dt.job.mode](dt)
    if finish == True:
        return stop(session, dt.job,
                        revoke=False)
    if issue == False:
        return

    task = dict()
    task_id = r_task_id(suffix=12)
    task["config"] = dt.job.config
    task["method"] = "v%s%s.%s" % (
                dt.job.script.parent.id, dt.job.script.id,
                dt.job.script.parent.entry["method"])
    function = "cb_task_params_{}".format(dt.job.param_source)
    new_id, params = globals().get(function)(task_id, dt)
    if params == None:
        return False
    task_id = new_id or task_id
    task["params"] = params
    task["args"] = params
    task["task_id"] = task_id

    execution = dict()
    execution["device"] = dt.device
    execution["script"] = dt.job.script
    execution["job"] = dt.job
    execution["state"] = TaskState.PENDING.value
    execution["task_id"] = task_id
    execution["params"] = params
    se = Task(**execution)
    session.add(se)
    session.flush()

    lock_job(session, dt.job.id)
    send_node_command("task/execute", task,
                                    dt.device.dev_id,
                                    correlation_id=None)
    session.query(DeviceJob).filter(DeviceJob.id == dt.id).update(dict(
                 issued=DeviceJob.issued + 1
    ), synchronize_session=False)
    dt.task_state = DeviceJobTaskState.PENDING.value
    dt.last_state_update_time = time.time()
    dt.last_issue_time = time.time()
    session.flush()
    session.query(Job).filter(Job.id == dt.job.id).update(dict(
                 issued=Job.issued + 1
    ), synchronize_session=False)
    return True


def cb_task_status_next(session, dt):
    dts = get_eligible_devicejobs(session, dt.device)
    if len(dts) == 0: return None
    dispatch = lambda dt: cb_task_status_dispatch(session, dt)
    weighted_issue_iter(dts, dispatch)


def cb_task_status_prepared(session, dt):
    lock = Redlock(key=f"issue-{dt.device.dev_id}",
                                auto_release_time=60*5,
                                masters=lockers)
    if lock.locked():
        return
    with lock:
        return cb_task_status_prepared_imp(session, dt)


def cb_task_status_dispatch(session, dt):
    function = "cb_task_status_{}".format(dt.state.replace("/", "_"))
    result = globals().get(function)(session, dt)
    return result == True


def event_handle_TASK_STATUS(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    if d is None or data["data"]["active"] > 0 or data["data"]["queued"] > 0:
        return None
    dts = get_eligible_devicejobs(session, d)
    if len(dts) == 0: return None
    dispatch = lambda dt: cb_task_status_dispatch(session, dt)
    weighted_issue_iter(dts, dispatch)


def event_handle_TASK_LOAD(session, data):
    jid = data["correlation_id"]
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    job = session.query(Job).filter(Job.id == jid).first()
    dt = session.query(DeviceJob).filter(DeviceJob.device_id==d.id,
                                  DeviceJob.job_id==job.id).first()
    should_bind = is_device_in_job_group(session, d, job)
    update_devicejob_binding_state(session, dt, should_bind)
    ok = data["data"]["loaded"] != False
    state = (DeviceJobState.SCRIPT_LOAD_FAILED.value, DeviceJobState.PREPARED.value)[ok]
    dt.state = state
    dt.error = None if ok else data["data"].get("error")
    dt.last_state_update_time = data["received"]
    session.flush()

    cb_task_status_prepared(session, dt)


def event_handle_TASK_EXECUTE(session, data):
    se = session.query(Task).filter(
                    Task.task_id==data["data"]["task_id"]).first()
    dt = session.query(DeviceJob).filter(DeviceJob.job_id == se.job_id,
                                DeviceJob.device_id == se.device_id).first()
    se.state = TaskState.ISSUED.value
    session.flush()

    dt.task_state = DeviceJobTaskState.ISSUED.value
    dt.last_state_update_time = time.time()
    session.flush()


def event_handle_TASK_PURGE(session, data):
    return None


def event_handle_TASK_REVOKE(session, data):
    d = session.query(Device).filter(Device.dev_id==data["device_id"]).first()
    session.query(Task).filter(Task.device_id==d.id,
                               Task.task_id.in_(data["data"]["task_id"]),
                               Task.finish_time==0).update(dict(
                                    state=TaskState.REVOKED.value,
                                    finish_time=data["received"]
                                                ), synchronize_session=False)
    for task_id in data["data"]["task_id"]:
        increase_devicejob_revoked(session, task_id)


def cb_message_file(session, se, name, data, timestamp):
    resource = dict()
    resource["task"] = se
    resource["type"] = TaskResourceType.FILE.value
    resource["name"] = name
    resource["data"] = data
    resource["create_time"] = timestamp
    session.add(TaskResource(**resource))
    session.flush()


def cb_message_log(session, se, name, data, timestamp):
    resource = dict()
    resource["task"] = se
    resource["type"] = TaskResourceType.LOG.value
    resource["name"] = name
    resource["data"] = data
    resource["create_time"] = timestamp
    session.add(TaskResource(**resource))
    session.flush()


def cb_message_data(session, se, name, data, timestamp):
    resource = dict()
    resource["task"] = se
    resource["type"] = TaskResourceType.DATA.value
    resource["name"] = name
    resource["data"] = data
    resource["create_time"] = timestamp
    session.add(TaskResource(**resource))
    session.flush()


def cb_message_ai_tool(session, se, name, data, timestamp):
    resource = dict()
    resource["task"] = se
    resource["type"] = TaskResourceType.LOG.value
    resource["name"] = name
    arguments = json_dump(data['arguments'], ensure_ascii=False)
    message = f"tool: {data['name']}({arguments})"
    resource["data"] = dict(message=message)
    resource["create_time"] = timestamp
    session.add(TaskResource(**resource))
    session.flush()


def cb_message_ai_message(session, se, name, data, timestamp):
    resource = dict()
    resource["task"] = se
    resource["type"] = TaskResourceType.LOG.value
    resource["name"] = name
    message = f"{data['role']}: {data['content']}"
    resource["data"] = dict(message=message)
    resource["create_time"] = timestamp
    session.add(TaskResource(**resource))
    session.flush()


def cb_message_ai_usage(session, se, name, data, timestamp):
    session.query(ModelResource).filter(ModelResource.id == se.job.model.id).update(dict(
        token_count=ModelResource.token_count + data["total_tokens"]
    ), synchronize_session=False)


def event_handle_TASK_MESSAGE(session, data):
    se = session.query(Task).filter(
                    Task.task_id==data["data"]["task_id"]).first()
    function = "cb_message_{}".format(data["data"]["data"]["type"].replace("/", "_"))
    globals().get(function)(session, se, data["data"]["data"].get("name"),
                                data["data"]["data"].get("data"),
                                data["timestamp"])


def event_handle_TASK_STARTED(session, data):
    se = session.query(Task).filter(
                    Task.task_id==data["data"]["task_id"]).first()
    dt = session.query(DeviceJob).filter(DeviceJob.job_id == se.job_id,
                                DeviceJob.device_id == se.device_id).first()
    se.state = TaskState.RUNNING.value
    se.start_time = data["received"]
    session.flush()

    dt.task_state = DeviceJobTaskState.RUNNING.value
    dt.last_state_update_time = time.time()
    session.flush()


def event_handle_TASK_RETRIED(session, data):
    se = session.query(Task).filter(
                    Task.task_id==data["data"]["task_id"]).first()
    return None


def event_handle_TASK_REVOKED(session, data):
    se = session.query(Task).filter(
                    Task.task_id==data["data"]["task_id"]).first()
    dt = session.query(DeviceJob).filter(DeviceJob.job_id == se.job_id,
                                DeviceJob.device_id == se.device_id).first()
    se.finish_time = data["received"]
    se.reason = "REVOKED"
    se.state = TaskState.REVOKED.value
    session.flush()
    lock_job(session, se.job.id)
    dt.task_state = DeviceJobTaskState.IDLE.value
    dt.last_state_update_time = time.time()
    session.flush()

    session.query(Job).filter(Job.id == se.job.id).update(dict(
                 revoked=Job.revoked + 1
    ), synchronize_session=False)

    session.query(DeviceJob).filter(DeviceJob.id == dt.id).update(dict(
                 revoked=DeviceJob.revoked + 1,
    ), synchronize_session=False)

    report_task_result(dt, se)


def event_handle_TASK_SUCCEEDED(session, data):
    se = session.query(Task).filter(
                    Task.task_id==data["data"]["task_id"]).first()
    dt = session.query(DeviceJob).filter(DeviceJob.job_id == se.job_id,
                                DeviceJob.device_id == se.device_id).first()

    se.result = data["data"]["result"]
    se.finish_time = data["received"]
    se.elapsed_time = data["data"]["runtime"]
    se.reason = "SUCCESS"
    se.state = TaskState.SUCCESS.value
    session.flush()
    lock_job(session, se.job.id)
    dt.task_state = DeviceJobTaskState.IDLE.value
    dt.last_state_update_time = time.time()
    session.flush()

    session.query(Job).filter(Job.id == se.job.id).update(dict(
                 success=Job.success + 1
    ), synchronize_session=False)

    session.query(DeviceJob).filter(DeviceJob.id == dt.id).update(dict(
                 success=DeviceJob.success + 1,
    ), synchronize_session=False)

    report_task_result(dt, se)
    cb_task_status_next(session, dt)


def event_handle_TASK_FAILED(session, data):
    se = session.query(Task).filter(
                    Task.task_id==data["data"]["task_id"]).first()
    dt = session.query(DeviceJob).filter(DeviceJob.job_id == se.job_id,
                                DeviceJob.device_id == se.device_id).first()
    timeout = 1 if data["data"].get("timeout") else 0
    failed  = 0 if timeout else 1

    se.finish_time = data["received"]
    se.state = TaskState.TIMEOUT.value if timeout else TaskState.FAILED.value
    exception = data["data"].get("exception")

    se.exception = exception
    se.traceback = data["data"].get("traceback")
    se.reason = exception.get("metadata", {}).get("reason") \
                if isinstance(exception, dict) else None
    session.flush()
    lock_job(session, se.job.id)
    if isinstance(exception, dict) and exception.get(
                            "type") == "NotRegistered":
        dt.state = DeviceJobState.INITIAL.value
    dt.task_state = DeviceJobTaskState.IDLE.value
    dt.last_state_update_time = time.time()
    session.flush()

    session.query(Job).filter(Job.id == se.job.id).update(dict(
                 failed =Job.failed  + failed,
                 timeout=Job.timeout + timeout,
    ), synchronize_session=False)

    session.query(DeviceJob).filter(DeviceJob.id == dt.id).update(dict(
                 failed =DeviceJob.failed  + failed,
                 timeout=DeviceJob.timeout + timeout,
    ), synchronize_session=False)

    report_task_result(dt, se)
    cb_task_status_next(session, dt)


def handle_event(name, data):
    with session_scope() as session:
        globals().get("event_handle_{}".format(name)
                                    )(session, data)


@app.task(bind=True)
def handle(self, device_id, payload):
    event = msgpack_load(payload)
    event_type = event["type"]
    payload = event["payload"]
    handle_event(event_type, payload)
    next_payload = pop_next_event(device_id)
    if next_payload:
        handle.apply_async((device_id, next_payload),
                                                ignore_result=True,
                                                    countdown=0)


@app.task(bind=True)
def sync(self):
    lock = Redlock(key="sync",
                                auto_release_time=60*10,
                                masters=lockers)
    with lock:
        with session_scope() as session:
            ensure_devicejob_records_batch(session)
            sync_devicejob_binding_batch(session)
            mark_lost_tasks_batch(session)


@app.task(bind=True)
def issue_task_by_devicejob_id(self, id):
    with session_scope() as session:
        dt = session.query(DeviceJob).filter(DeviceJob.id==id).first()
        cb_task_status_dispatch(session, dt)


@app.task(bind=True)
def issue_task_by_job(self, id):
    with session_scope() as session:
        ids = [dt.id for dt in session.query(DeviceJob).join(Device).filter(
                        DeviceJob.job_id == id,
                        Device.state == DeviceState.ONLINE.value,
        ).all()]
    for djid in ids:
        issue_task_by_devicejob_id.apply_async((djid,),
                                                ignore_result=True,
                                                    countdown=0)
