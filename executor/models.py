# Copyright 2022 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import os
import time
import functools
from enum import Enum
from contextlib import contextmanager
from sqlalchemy.dialects.postgresql import insert

from datetime import datetime
from sqlalchemy import text, inspect
from dateutil.relativedelta import relativedelta

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Float,
    ForeignKey,
    Integer,
    BigInteger,
    String,
    Text,
    Double,
    create_engine,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship, scoped_session, sessionmaker
from sqlalchemy.types import JSON
from sqlalchemy_serializer import SerializerMixin

from .utils import r_string


class StringEnum(str, Enum):
    pass


class DeviceState(StringEnum):
    PENDING = "pending"
    OFFLINE = "offline"
    ONLINE = "online"


class ParamSource(StringEnum):
    NATIVE = "native"
    CALLBACK = "callback"
    QUEUE = "queue"


class JobMode(StringEnum):
    LOOP = "loop"
    COUNT = "count"
    DEADLINE = "deadline"
    CRONTAB = "crontab"
    PER_DEVICE_COUNT = "per-device-count"


class JobState(StringEnum):
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"


class DeviceMode(StringEnum):
    P2P = "p2p"
    DIRECT = "direct"
    FORWARD = "forward"
    ONEWAY = "oneway"


class DeviceJobState(StringEnum):
    INITIAL = "initial"
    SCRIPT_ISSUED = "script/issued"
    SCRIPT_ACCEPTED = "script/accepted"
    SCRIPT_LOAD_FAILED = "script/load_failed"
    PREPARED = "prepared"


class DeviceJobTaskState(StringEnum):
    INITIAL = "initial"
    IDLE = "idle"
    PENDING = "pending"
    ISSUED = "issued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    REVOKED = "revoked"
    TIMEOUT = "timeout"


class ModelProvider(StringEnum):
    OPENAI_COMPATIBLE = "openai_compatible"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class DeviceJobBindingState(StringEnum):
    ACTIVE = "active"
    REMOVED = "removed"


class TaskState(StringEnum):
    PENDING = "pending"
    ISSUED = "issued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    REVOKED = "revoked"
    TIMEOUT = "timeout"
    LOST = "lost"


class TaskResourceType(StringEnum):
    DATA = "data"
    FILE = "file"
    LOG = "log"


class ActivityCategory(StringEnum):
    DEVICE = "device"
    JOB = "job"


class ActivitySeverity(StringEnum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    FAILED = "failed"


class FirmwareVariant(StringEnum):
    ARM64_V8A = "arm64-v8a"
    ARMEABI_V7A = "armeabi-v7a"
    X86 = "x86"
    X86_64 = "x86_64"


engine = create_engine(f"postgresql+psycopg://postgres:{os.environ['POSTGRES_PASSWORD']}@127.0.0.1:6432/pigeon", pool_size=8, max_overflow=8, pool_recycle=300, pool_timeout=30, pool_pre_ping=True)
Session = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=True, expire_on_commit=False))
Base = declarative_base()


@contextmanager
def session_scope():
    with Session() as session:
        with session.begin():
            yield session


class BaseDatabaseModel(Base, SerializerMixin):
    __abstract__ = True
    id = Column(Integer, primary_key=True)


class Config(BaseDatabaseModel):
    __tablename__ = "config"
    name                = Column(String, unique=True, index=True)
    value               = Column(String(65535))
    @classmethod
    def get(cls, name):
        with session_scope() as session:
            cfg = session.query(cls).filter(cls.name==name).first()
            return cfg.value if cfg else None
    @classmethod
    def upsert(cls, name, value):
        with session_scope() as session:
            session.execute(insert(cls).values(name=name, value=value).on_conflict_do_update(
                                index_elements=[cls.name],
                                set_={"value": insert(cls).excluded.value}))


class User(BaseDatabaseModel):
    __tablename__ = "user"
    name                = Column(String, unique=True, index=True)
    contact             = Column(String, nullable=True, index=True)

    password            = Column(String)
    token               = Column(String, default=r_string)

    last_login_ip       = Column(String, nullable=True)

    register_time       = Column(BigInteger, default=time.time)
    last_login_time     = Column(BigInteger, default=0)
    is_admin            = Column(Boolean, default=False)

    owned_scripts = relationship("Script", back_populates="owner", lazy="dynamic")
    models = relationship("ModelResource", back_populates="owner", lazy="dynamic")
    firmwares = relationship("Firmware", back_populates="owner", lazy="dynamic")
    jobs = relationship("Job", back_populates="owner", lazy="dynamic")
    groups = relationship("Group", back_populates="owner", lazy="dynamic")


class Script(BaseDatabaseModel):
    __tablename__ = "script"
    name                = Column(String(255), unique=True)
    description         = Column(Text, nullable=True)
    owner_id            = Column(Integer, ForeignKey("user.id"))
    type                = Column(Integer, default=0)
    entry               = Column(JSON, default=dict, nullable=True)
    create_time         = Column(BigInteger, default=time.time)
    is_deleted          = Column(Boolean, default=False)

    owner = relationship("User", back_populates="owned_scripts")
    versions = relationship("ScriptVersion", back_populates="parent", lazy="dynamic")


class ScriptVersion(BaseDatabaseModel):
    __tablename__ = "scriptversion"
    version             = Column(String)
    change_log          = Column(Text, nullable=True)
    code                = Column(Text)
    parent_id           = Column(Integer, ForeignKey("script.id", ondelete="CASCADE"))
    create_time         = Column(BigInteger, default=time.time)

    __table_args__ = (
        UniqueConstraint("parent_id", "version", name="scriptversion_parent_version_uniq"),
    )

    parent = relationship("Script", back_populates="versions")


class ModelResource(BaseDatabaseModel):
    __tablename__ = "modelresource"
    name                = Column(String(255), unique=True)
    description         = Column(Text, nullable=True)
    owner_id            = Column(Integer, ForeignKey("user.id"))

    provider            = Column(String, default=ModelProvider.OPENAI_COMPATIBLE.value, index=True)
    api_base            = Column(String, nullable=True)
    api_key             = Column(String, nullable=True)

    model_name          = Column(String, nullable=True)
    context_window      = Column(Integer, default=256*1024)

    vision_mode         = Column(Boolean, default=False)
    vision_scale        = Column(Integer, default=0)

    step_delay          = Column(Float, nullable=True, default=0.0)
    max_completion_tokens= Column(Integer, default=4096)
    temperature         = Column(Float, nullable=True, default=0.0)

    token_count         = Column(BigInteger, default=0)
    create_time         = Column(BigInteger, default=time.time)

    __table_args__ = (
        CheckConstraint("temperature >= 0.1 AND temperature <= 1.0", name="modelresource_temperature_check"),
    )

    owner = relationship("User", back_populates="models")


class Job(BaseDatabaseModel):
    __tablename__ = "job"
    name                = Column(String(255))
    description         = Column(Text, nullable=True)
    owner_id            = Column(Integer, ForeignKey("user.id"))
    group_id            = Column(Integer, ForeignKey("group.id", ondelete="SET NULL"), nullable=True)

    script_id           = Column(Integer, ForeignKey("scriptversion.id"))
    config              = Column(JSON, default=dict, nullable=True)
    priority            = Column(Integer, default=50)

    model_id            = Column(Integer, ForeignKey("modelresource.id", ondelete="SET NULL"), nullable=True)

    params              = Column(JSON, default=dict, nullable=True)
    param_source        = Column(String, default=ParamSource.NATIVE.value)

    mode                = Column(String, default=JobMode.LOOP.value)
    interval            = Column(BigInteger, default=0)
    crontab             = Column(String, default="", nullable=True)
    count               = Column(BigInteger, default=0)
    issued              = Column(BigInteger, default=0)
    state               = Column(String, default=JobState.RUNNING.value)

    success             = Column(BigInteger, default=0)
    failed              = Column(BigInteger, default=0)
    timeout             = Column(BigInteger, default=0)
    revoked             = Column(BigInteger, default=0)

    create_time         = Column(BigInteger, default=time.time)
    start_time          = Column(BigInteger, default=0)
    stop_time           = Column(BigInteger, default=0)

    __table_args__ = (
        CheckConstraint("priority >= 1 AND priority <= 100", name="job_priority_check"),
    )

    owner = relationship("User", back_populates="jobs")
    group = relationship("Group", back_populates="jobs")
    script = relationship("ScriptVersion")
    model = relationship("ModelResource")


class UserScript(BaseDatabaseModel):
    __tablename__ = "userscript"
    user_id              = Column(Integer, ForeignKey("user.id", ondelete="CASCADE"))
    script_id            = Column(Integer, ForeignKey("script.id", ondelete="CASCADE"))

    __table_args__ = (
        UniqueConstraint("user_id", "script_id", name="userscript_user_script_uniq"),
    )


class Device(BaseDatabaseModel):
    __tablename__ = "device"
    domain              = Column(String, unique=True, index=True)
    dev_id              = Column(String, nullable=True, index=True)
    token_id            = Column(String, unique=True, index=True)

    serialno            = Column(String, nullable=True, index=True)

    mode                = Column(String, default=DeviceMode.P2P.value)

    comment             = Column(String(4096), nullable=True)

    service_port        = Column(Integer, default=65000)
    privileged          = Column(Boolean, default=True)

    top_ip              = Column(String, nullable=True)
    vpn_ip              = Column(String, nullable=True)
    default_ip          = Column(String, nullable=True)

    boot_time           = Column(BigInteger, nullable=True, default=0)

    batt_percent        = Column(Float, nullable=True, default=0.0)

    disk_total          = Column(BigInteger, nullable=True, default=0)
    disk_used           = Column(BigInteger, nullable=True, default=0)
    disk_percent        = Column(Float, nullable=True, default=0.0)

    mem_total           = Column(BigInteger, nullable=True, default=0)
    mem_used            = Column(BigInteger, nullable=True, default=0)
    mem_percent         = Column(Float, nullable=True, default=0.0)

    cpu_count           = Column(Integer, nullable=True, default=0)

    batt_charging       = Column(Boolean, nullable=True, default=False)
    api_available       = Column(Boolean, nullable=True, default=False)
    locked              = Column(Boolean, nullable=True, default=False)
    frida_token         = Column(String, nullable=True)
    lock_token          = Column(String, nullable=True)

    controlling         = Column(Boolean, nullable=True, default=False)
    controlling_cid     = Column(String, nullable=True)

    public_ip           = Column(String, nullable=True)
    ip_lat              = Column(Double, nullable=True, default=0.0)
    ip_lng              = Column(Double, nullable=True, default=0.0)
    ip_country          = Column(String, nullable=True)
    ip_region           = Column(String, nullable=True)
    ip_city             = Column(String, nullable=True)

    cert                = Column(String(8192), nullable=True)
    auth_token          = Column(String, nullable=True)

    brand               = Column(String, nullable=True)
    device              = Column(String, nullable=True)
    model               = Column(String, nullable=True)
    abi                 = Column(String, nullable=True)
    version             = Column(String, nullable=True)
    sdk                 = Column(String, nullable=True)
    hardware            = Column(String, nullable=True)
    board               = Column(String, nullable=True)

    is_deleted          = Column(Boolean, default=False, index=True)
    register_time       = Column(BigInteger, nullable=True, default=time.time)
    last_heartbeat_time = Column(BigInteger, nullable=True, default=0)
    state               = Column(String, default=DeviceState.PENDING.value)


class DeviceJob(BaseDatabaseModel):
    __tablename__ = "devicejob"
    device_id            = Column(Integer, ForeignKey("device.id", ondelete="CASCADE"))
    job_id               = Column(Integer, ForeignKey("job.id", ondelete="CASCADE"))
    state                = Column(String, default=DeviceJobState.INITIAL.value, index=True)
    last_state_update_time = Column(BigInteger, default=0)
    error                = Column(Text, nullable=True)

    task_state           = Column(String, default=DeviceJobTaskState.IDLE.value, index=True)
    binding_state        = Column(String, default=DeviceJobBindingState.ACTIVE.value, index=True)

    issued               = Column(BigInteger, default=0)
    credit               = Column(Float, default=0)

    last_issue_time      = Column(BigInteger, default=0)
    cooldown             = Column(BigInteger, default=0)

    success              = Column(BigInteger, default=0)
    failed               = Column(BigInteger, default=0)
    timeout              = Column(BigInteger, default=0)
    revoked              = Column(BigInteger, default=0)
    create_time          = Column(BigInteger, default=time.time)
    leave_time           = Column(BigInteger, default=0)

    __table_args__ = (
        UniqueConstraint("device_id", "job_id", name="devicejob_device_job_uniq"),
    )

    device = relationship("Device", back_populates="devicejobs")
    job = relationship("Job", back_populates="devicejobs")


class Group(BaseDatabaseModel):
    __tablename__ = "group"
    owner_id            = Column(Integer, ForeignKey("user.id"), index=True)

    name                = Column(String, index=True)
    description         = Column(Text, nullable=True)

    order               = Column(Integer, default=0)

    color               = Column(String, default="#34db77")
    create_time         = Column(BigInteger, default=time.time)
    update_time         = Column(BigInteger, default=time.time)

    __table_args__ = (
        UniqueConstraint("owner_id", "name", name="group_owner_name_uniq"),
    )

    owner = relationship("User", back_populates="groups")
    jobs = relationship("Job", back_populates="group")

    @property
    def devices(self):
        return Session().query(Device).join(UserDevice, UserDevice.device_id == Device.id).filter(
                UserDevice.group_id == self.id,
                Device.is_deleted == False,
        )


class UserDevice(BaseDatabaseModel):
    __tablename__ = "userdevice"
    device_id            = Column(Integer, ForeignKey("device.id", ondelete="CASCADE"))
    user_id              = Column(Integer, ForeignKey("user.id", ondelete="CASCADE"))
    group_id             = Column(Integer, ForeignKey("group.id", ondelete="SET NULL"), nullable=True)

    __table_args__ = (
        UniqueConstraint("user_id", "device_id", name="userdevice_user_device_uniq"),
        Index("userdevice_user_group_idx", "user_id", "group_id"),
        Index("userdevice_device_user_idx", "device_id", "user_id"),
    )


class DeviceStatus(BaseDatabaseModel):
    __tablename__ = "devicestatus"
    device_id            = Column(Integer, ForeignKey("device.id"))
    batt_temperature     = Column(Float, default=0)
    batt_percent         = Column(Float, default=0)

    core_temperature     = Column(Float, default=0)
    cpu_percent          = Column(Integer, default=0)
    cpu_freq_current     = Column(Float, default=0)
    cpu_freq_max         = Column(Float, default=0)
    cpu_freq_min         = Column(Float, default=0)
    cpu_times_user       = Column(Float, default=0)
    cpu_times_system     = Column(Float, default=0)
    cpu_times_idle       = Column(Float, default=0)

    disk_used            = Column(BigInteger, default=0)
    disk_free            = Column(BigInteger, default=0)
    disk_percent         = Column(Float, default=0)

    disk_io_read_bytes   = Column(BigInteger, default=0)
    disk_io_read_count   = Column(BigInteger, default=0)
    disk_io_write_bytes  = Column(BigInteger, default=0)
    disk_io_write_count  = Column(BigInteger, default=0)
    disk_io_read_time    = Column(BigInteger, default=0)
    disk_io_write_time   = Column(BigInteger, default=0)
    disk_io_busy_time    = Column(BigInteger, default=0)

    net_io_bytes_sent    = Column(BigInteger, default=0)
    net_io_packets_sent  = Column(BigInteger, default=0)
    net_io_bytes_recv    = Column(BigInteger, default=0)
    net_io_packets_recv  = Column(BigInteger, default=0)

    mem_available        = Column(BigInteger, default=0)
    mem_percent          = Column(Float, default=0)
    mem_used             = Column(BigInteger, default=0)
    mem_free             = Column(BigInteger, default=0)
    mem_active           = Column(BigInteger, default=0)
    mem_inactive         = Column(BigInteger, default=0)
    mem_buffers          = Column(BigInteger, default=0)
    mem_cached           = Column(BigInteger, default=0)
    mem_shared           = Column(BigInteger, default=0)
    mem_slab             = Column(BigInteger, default=0)

    process_count        = Column(Integer, default=0)
    thread_count         = Column(Integer, default=0)
    fd_count             = Column(Integer, default=0)
    crash_count          = Column(Integer, default=0)
    udpcon_count         = Column(Integer, default=0)
    tcpcon_count         = Column(Integer, default=0)

    wlan_linkspeed       = Column(Integer, default=0)
    wlan_freq            = Column(Integer, default=0)
    wlan_rssi            = Column(Integer, default=0)
    timestamp            = Column(BigInteger, default=time.time, index=True)


class Task(BaseDatabaseModel):
    __tablename__ = "task"
    device_id            = Column(Integer, ForeignKey("device.id"))
    script_id            = Column(Integer, ForeignKey("scriptversion.id"))
    job_id               = Column(Integer, ForeignKey("job.id"))

    task_id              = Column(String(255), unique=True)
    params               = Column(JSON, default=dict, nullable=True)
    state                = Column(String, default=TaskState.PENDING.value, index=True)

    result               = Column(JSON, default=None, nullable=True)

    reason               = Column(String, nullable=True, index=True)
    exception            = Column(JSON, default=None, nullable=True)
    traceback            = Column(Text, nullable=True)

    elapsed_time         = Column(Float, default=0)

    start_time           = Column(BigInteger, default=0)
    finish_time          = Column(BigInteger, default=0)
    create_time          = Column(BigInteger, default=time.time, index=True)

    device = relationship("Device", back_populates="tasks")
    script = relationship("ScriptVersion")
    job = relationship("Job", back_populates="tasks")


class TaskResource(BaseDatabaseModel):
    __tablename__ = "taskresource"
    task_id              = Column(Integer, ForeignKey("task.id"))
    type                 = Column(String, default=TaskResourceType.DATA.value, index=True)
    name                 = Column(String, nullable=True, index=True)
    data                 = Column(JSON, default=None, nullable=True)

    create_time          = Column(BigInteger, default=time.time, index=True)

    task = relationship("Task", back_populates="resources")


class Activity(BaseDatabaseModel):
    __tablename__ = "activity"
    job_id               = Column(Integer, ForeignKey("job.id", ondelete="CASCADE"), nullable=True)
    device_id            = Column(Integer, ForeignKey("device.id", ondelete="CASCADE"), nullable=True)
    category             = Column(String(32), index=True, default=ActivityCategory.DEVICE.value)
    action               = Column(String(64), index=True)
    severity             = Column(String(16), index=True, default=ActivitySeverity.INFO.value)
    message              = Column(Text, nullable=True)
    meta                 = Column(JSON, default=dict, nullable=True)
    create_time          = Column(BigInteger, default=time.time, index=True)


class Firmware(BaseDatabaseModel):
    __tablename__ = "firmware"
    owner_id = Column(Integer, ForeignKey("user.id"), index=True)

    version             = Column(String(50), nullable=False)
    variant             = Column(String, default=FirmwareVariant.ARM64_V8A.value, index=True)

    file_path           = Column(String(500), nullable=True)
    download_url        = Column(Text, nullable=True)

    file_size           = Column(Integer, nullable=True)
    md5_checksum        = Column(String(32), nullable=True)
    release_notes       = Column(Text, nullable=True)

    is_active           = Column(Boolean, default=True)

    update_time         = Column(BigInteger, default=time.time, onupdate=time.time)
    create_time         = Column(BigInteger, default=time.time, index=True)

    owner = relationship("User", back_populates="firmwares")

    __table_args__ = (
        Index("idx_unique_variant_version", "variant", "version", unique=True),
        Index("idx_variant_active", "variant", "is_active"),
    )

Device.devicejobs = relationship("DeviceJob", back_populates="device", lazy="dynamic")
Device.tasks = relationship("Task", back_populates="device", lazy="dynamic")
Device.status = relationship("DeviceStatus", lazy="dynamic")
Device.activities = relationship("Activity", lazy="dynamic")
Job.devicejobs = relationship("DeviceJob", back_populates="job", lazy="dynamic")
Job.tasks = relationship("Task", back_populates="job", lazy="dynamic")
Job.activities = relationship("Activity", lazy="dynamic")
Task.resources = relationship("TaskResource", back_populates="task", lazy="dynamic")

Model = BaseDatabaseModel


class PartitionManager(object):
    def __init__(self, engine):
        self.engine = engine
    def ensure(self, model, ts):
        target_dt = datetime.fromtimestamp(ts)
        start = target_dt.date().replace(day=1)
        end = start + relativedelta(months=1)
        suffix = start.strftime('%Y_%m')
        return self._execute(model, start, end, suffix)
    def _execute(self, model, start, end, suffix):
        table = model.__tablename__
        schema = inspect(model).selectable.schema
        parent = f'"{schema}"."{table}"' if schema else f'"{table}"'
        name = f"{table}_{suffix}"
        partition = f'"{schema}"."{name}"' if schema else f'"{name}"'
        sql = text(f"""
        CREATE TABLE IF NOT EXISTS {partition}
        PARTITION OF {parent}
        FOR VALUES FROM ('{start}') TO ('{end}');""")
        with self.engine.begin() as conn:
            conn.execute(sql)
