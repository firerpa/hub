# Copyright 2022 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import os
import io
import re
import time
import uuid
import json
import functools
import shlex
import random
import shutil
import socket
import string
import logging
import platform
import psutil
import asyncio
import uvloop
import importlib
import requests
import ipaddress
import subprocess
import pem as Pem
import tornado.web
import tornado.ioloop
import cachetools.func
import threading
import traceback
import redis

from pathlib import Path
from ipaddress import ip_network
from hashlib import sha256
from base64 import b64encode
from collections import OrderedDict
from urllib.parse import urlparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from OpenSSL import crypto
from datetime import datetime
from sqlalchemy import func as fn, case, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from msgpack import dumps as msgpack_dump, loads as msgpack_load
from tornado import httputil
from lamda.client import Device as GrpcDevice
from tornado.ioloop import IOLoop
from tornado.web import Application, HTTPError
from tornado.websocket import WebSocketHandler
from tornado.netutil import bind_sockets
from tornado.httpserver import HTTPServer

from executor.models import *
from executor.handlers.event import stop, sync
from executor.config import aiodb, db
from executor.utils import *
from executor.top import *

from . import __version__


M_OP_MAP = {
    "eq":   lambda f, v: f == v,
    "gt":   lambda f, v: f > v,
    "ge":   lambda f, v: f >= v,
    "lt":   lambda f, v: f < v,
    "le":   lambda f, v: f <= v,
    "neq":  lambda f, v: f != v,
    "like": lambda f, v: f.contains(v),
    "in":   lambda f, v: f.in_(v),
}

logger = logging.getLogger()


def get_unique_free_port(session, start, end):
    occupied_ports = set(session.scalars(select(Device.service_port).where(
                                    Device.mode == DeviceMode.FORWARD.value,
                                    Device.is_deleted == False)).all())
    for _ in range(128):
        port = random.randint(start, end)
        if port in occupied_ports:
            continue
        lock_key = f"frp:ports:{port}"
        if db.set(lock_key, "1", ex=300, nx=True):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("0.0.0.0", port))
                    return port
                except socket.error:
                    continue


def Case(value, whens, default):
    return case(*whens, value=value, else_=default)


def qpaginate(query, page, size):
    page = max(1, int(page))
    size = max(1, int(size))
    return query.offset((page - 1) * size).limit(size)


class WaitableTaskQueue(object):
    def __init__(self, job):
        self.job = job
    async def send(self, params, task_id=None,
                                domain=None):
        task_id = task_id or r_task_id()
        data = msgpack_dump({"task_id": task_id, "params": params})
        queue = f"job:{self.job.id}:{domain if domain else ''}"
        await aiodb.rpush(queue, data)
    async def wait(self, params, task_id=None, domain=None,
                                                timeout=120,
                                                throw=None):
        task_id = task_id or r_task_id()
        channel = f"job:result:{task_id}"
        pubsub = aiodb.pubsub()
        await pubsub.subscribe(channel)
        try:
            await self.send(params, task_id, domain)
            return await asyncio.wait_for(self._listen_once(pubsub),
                                                timeout=timeout)
        except asyncio.TimeoutError:
            throw and throw()
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
    async def _listen_once(self, pubsub):
        async for message in pubsub.listen():
            if message["type"] == "message":
                return msgpack_load(message["data"])


class HttpServiceManager(object):
    def __init__(self, port=8800):
        self.handlers = OrderedDict()
        pkg_dir = os.path.dirname(__file__)
        self.static = os.path.join(pkg_dir, "static")
        self.template = os.path.join(pkg_dir, "html")
        self.port = port

    def add_handler(self, route, name, *args,
                                    handler="Handler"):
        handle = getattr(importlib.import_module(name),
                                            handler)
        self.handlers[route] = (route, handle, *args)

    def start_server(self, **settings):
        loop = uvloop.new_event_loop()
        asyncio.set_event_loop(loop)
        self.ioloop = IOLoop.current()
        kwargs = {}
        kwargs["debug"] = False
        kwargs["template_path"] = self.template
        kwargs["compiled_template_cache"] = True
        kwargs["default_handler_class"] = DefaultHttpService
        kwargs["static_path"] = self.static
        kwargs.update(settings)
        http = Application(self.handlers.values(),
                                        **kwargs)

        kwargs = {}
        kwargs["max_buffer_size"] = 33554432
        kwargs["xheaders"] = True
        server = HTTPServer(http, **kwargs)

        sockets = bind_sockets(self.port, address="127.0.0.1")
        server.add_sockets(sockets)
        self.ioloop.start()


def with_session(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        session = kwargs.pop("session", None)
        if session is not None:
            return func(self, session, *args, **kwargs)
        with session_scope() as session:
            return func(self, session, *args, **kwargs)
    return wrapper


class BaseHttpService(tornado.web.RequestHandler):
    def get_argument(self, name, default=tornado.web._ARG_DEFAULT, type=str):
        try:
            return type(super().get_argument(name, default=default))
        except ValueError:
            raise HTTPError(400, "Invalid type %s" % name)

    @with_session
    def get_login_user(self, session):
        cname = self.get_secure_cookie("token")
        cname = cname.decode() if isinstance(cname, (bytes, bytearray)) else cname
        xname = self.request.headers.get("X-User", "")
        xauth = self.request.headers.get("X-Auth", "")
        user = session.query(User).filter(User.name == cname).first()
        user = user or session.query(User).filter((User.name == xname) & (User.token == xauth)).first()
        user or self.throw(401, "A1001", message="Unauthorized user")
        return user

    @with_session
    def get_user_with_password(self, session, name, password):
        user = session.query(User).filter((User.name == name) & (User.password == password)).first()
        user or self.throw(400, "A1002", message="Invalid username or password")
        return user

    @with_session
    def get_login_user_device(self, session, domain, user=None):
        _ = self.get_device_by_domain(domain, session=session)
        user = user or self.get_login_user(session=session)
        device = session.query(Device).join(UserDevice).filter(
            (UserDevice.user_id == user.id) & (Device.domain == domain) & (Device.is_deleted == False)
        ).first()
        device or self.throw(401, "D3001", message="Not the device owner")
        return user, device

    @with_session
    def get_script_by_id(self, session, script_id):
        script = session.query(Script).filter((Script.id == int(script_id)) & (Script.is_deleted == False)).first()
        script or self.throw(404, "S4001", message="Script does not exist")
        return script

    @with_session
    def get_login_user_script(self, session, script_id, user=None):
        script = self.get_script_by_id(int(script_id), session=session)
        user = user or self.get_login_user(session=session)
        script = session.query(Script).join(UserScript).filter(
            (UserScript.user_id == user.id) & (UserScript.script_id == script.id)
        ).first()
        script or self.throw(401, "S4002", message="Not the script owner")
        return user, script

    @with_session
    def get_login_user_script_version(self, session, script_id, ver, user=None):
        user, script = self.get_login_user_script(script_id, user=user, session=session)
        version = session.query(ScriptVersion).filter(
            (ScriptVersion.parent_id == script.id) & (ScriptVersion.id == int(ver))
        ).first()
        version or self.throw(404, "V4101", message="Script version does not exist")
        return user, version

    @with_session
    def get_login_user_script_owner(self, session, script_id, user=None):
        script = self.get_script_by_id(int(script_id), session=session)
        user = user or self.get_login_user(session=session)
        script = session.query(Script).join(UserScript).filter(
            (Script.owner_id == user.id) & (UserScript.script_id == script.id)
        ).first()
        script or self.throw(401, "S4002", message="Not the script owner")
        return user, script

    @with_session
    def get_login_user_model(self, session, model_id, user=None):
        user = user or self.get_login_user(session=session)
        model = session.query(ModelResource).filter(
            ModelResource.owner_id == user.id, ModelResource.id == int(model_id)
        ).first()
        model or self.throw(401, "M8001", message="Not the model owner")
        return user, model

    @with_session
    def get_login_user_group(self, session, group_id, user=None):
        user = user or self.get_login_user(session=session)
        group = session.query(Group).filter(Group.owner_id == user.id, Group.id == int(group_id)).first()
        group or self.throw(401, "G6001", message="Group does not exist")
        return user, group

    @with_session
    def get_login_user_job_owner(self, session, job_id, user=None):
        user = user or self.get_login_user(session=session)
        job = session.query(Job).filter(Job.owner_id == user.id, Job.id == int(job_id)).first()
        job or self.throw(401, "J7001", message="Not the job owner")
        return user, job

    @with_session
    def get_login_user_admin(self, session):
        user = self.get_login_user(session=session)
        user.is_admin or self.throw(401, "A1003", message="Not a platform administrator user")
        return user

    @with_session
    def get_user_admin_or_self(self, session, uid):
        user = self.get_user_by_id(uid, session=session)
        current = self.get_login_user(session=session)
        (user.id == current.id or current.is_admin) or self.throw(401, "A1004", message="Only administrators or owners can operate")
        return user

    @with_session
    def remove_device_from_user(self, session, domain, user):
        user, device = self.get_login_user_device(domain, user=user, session=session)
        return session.query(UserDevice).filter(
            (UserDevice.user_id == user.id) & (UserDevice.device_id == device.id)
        ).delete(synchronize_session=False)

    @with_session
    def remove_script_from_user(self, session, script_id, user):
        user, script = self.get_login_user_script(script_id, user=user, session=session)
        return session.query(UserScript).filter(
            (UserScript.user_id == user.id) & (UserScript.script_id == script.id)
        ).delete(synchronize_session=False)

    @with_session
    def get_user_by_id(self, session, uid):
        uid_text = str(uid)
        uid_num = int(uid_text) if uid_text.isdigit() else -1
        user = session.query(User).filter((User.id == uid_num) | (User.name == uid_text)).first()
        user or self.throw(404, "U2002", message="User does not exist")
        return user

    @with_session
    def get_normal_user_by_id(self, session, uid):
        user = self.get_user_by_id(uid, session=session)
        user.is_admin and self.throw(401, "U2004", message="Target user cannot be an administrator")
        return user

    @with_session
    def get_device_by_domain(self, session, domain):
        device = session.query(Device).filter(Device.domain == domain, Device.is_deleted == False).first()
        device or self.throw(404, "D3002", message="Device does not exist")
        return device

    @with_session
    def get_device_by_token(self, session, token):
        device = session.query(Device).filter(Device.token_id == token, Device.is_deleted == False).first()
        device or self.throw(404, "D3002", message="Device does not exist")
        return device

    @with_session
    def alloc_device_to_user(self, session, domain, user):
        device = self.get_device_by_domain(domain, session=session)
        stmt = pg_insert(UserDevice).values(user_id=user.id, device_id=device.id)
        stmt = stmt.on_conflict_do_nothing(index_elements=[UserDevice.user_id, UserDevice.device_id]).returning(UserDevice.id)
        row = session.execute(stmt).first()
        row or self.throw(400, "D3003", message="The user already owns the device")
        return session.query(UserDevice).filter(UserDevice.id == row.id).first()

    @with_session
    def alloc_script_to_user(self, session, script_id, user):
        script = self.get_script_by_id(script_id, session=session)
        stmt = pg_insert(UserScript).values(user_id=user.id, script_id=script.id)
        stmt = stmt.on_conflict_do_nothing(index_elements=[UserScript.user_id, UserScript.script_id]).returning(UserScript.id)
        row = session.execute(stmt).first()
        row or self.throw(400, "S4006", message="The user already owns the script")
        return session.query(UserScript).filter(UserScript.id == row.id).first()

    @with_session
    def create_user(self, session, name, contact, **kwargs):
        re.match("^[a-zA-Z0-9_]{2,32}$", name) or self.throw(400, "U2001", message="Invalid username")
        meta = kwargs.copy()
        meta["last_login_ip"] = "0.0.0.0"
        meta["contact"] = contact
        meta["name"] = name
        stmt = pg_insert(User).values(**meta)
        stmt = stmt.on_conflict_do_nothing(index_elements=[User.name]).returning(User.id)
        row = session.execute(stmt).first()
        row or self.throw(400, "U2003", message="User already exists")
        return session.query(User).filter(User.id == row.id).first()

    def parse_filter(self, model, item):
        field = getattr(model, item["field"])
        return M_OP_MAP[item.get("op", "eq")](field, item["value"])

    def query_to_model_filter(self, model):
        filtor = self.get_argument("filter", "[]", type=json.loads)
        return [self.parse_filter(model, item) for item in filtor]

    def write_error(self, status, exc_info=None, **kwargs):
        error = self._reason
        self._reason = httputil.responses.get(status, "Unknown")
        try:
            self.finish({"status": status, "error": error, "message": exc_info[1].log_message})
        except AttributeError:
            traceback.print_exception(*exc_info)
            self.finish({"status": 500, "error": "X9001", "message": "Internal Server Error"})

    def on_finish(self):
        Session.remove()

    def __init__(self, *args, **kwargs):
        super(BaseHttpService, self).__init__(*args, **kwargs)
        self.ioloop = tornado.ioloop.IOLoop.current()
        self.ctl = self.application.settings["ctl"]

    async def call_sync_async(self, func, *args):
        return await self.ioloop.run_in_executor(None, func, *args)

    def timestamp(self):
        return int(time.time())

    def tell(self, response, **kwargs):
        data = dict(status=0, message=None)
        data.update(kwargs)
        data["data"] = response
        self.write(data)

    def throw(self, status, error=None, message=None):
        raise HTTPError(status, reason=error, log_message=message)


class DefaultHttpService(BaseHttpService):
    def prepare(self, *args, **kwargs):
        raise HTTPError(404)


class PlatformValidateHandler(BaseHttpService):
    def head_default(self, domain):
        u, _ = self.get_login_user_device(domain)
        self.set_header("X-ClientId", u.name)
    def head_mqtt(self, _):
        u = self.get_login_user_admin()
        self.set_header("X-ClientId", u.name)
    def head(self, domain):
        func = getattr(self, f"head_{domain}",
                            self.head_default)
        func(domain)


class PlatformSummaryInfoHandler(BaseHttpService):
    @cachetools.func.ttl_cache(ttl=5)
    def get_info(self, *args):
        with session_scope() as session:
            user = self.get_login_user(session=session)
            sel = session.query(Device).join(UserDevice).filter(
                                    UserDevice.user_id==user.id,
                                    Device.is_deleted==False)
            total = sel.count()
            usable = sel.filter( (Device.state==DeviceState.ONLINE.value)
                               & (Device.locked==False)).count()
            working = sel.filter((Device.state==DeviceState.ONLINE.value)
                               & (Device.locked==True) ).count()
            offline = sel.filter((Device.state==DeviceState.OFFLINE.value)
                                                        ).count()
        res = {}
        res["usable"]   = usable
        res["offline"]  = offline
        res["working"]  = working
        res["total"]    = total
        return res
    async def get(self, *args):
        res = await self.call_sync_async(self.get_info)
        self.tell(res)


class PlatformSpecificDeviceHandler(BaseHttpService):
    def to_dict(self, r):
        d = r.to_dict(only=("domain",
                            "dev_id",
                            "token_id",
                            "mode",
                            "comment",
                            "service_port",
                            "privileged",
                            "top_ip",
                            "vpn_ip",
                            "default_ip",
                            "boot_time",
                            "batt_percent",
                            "disk_total",
                            "disk_used",
                            "disk_percent",
                            "mem_total",
                            "mem_used",
                            "mem_percent",
                            "cpu_count",
                            "batt_charging",
                            "api_available",
                            "locked",
                            "controlling",
                            "controlling_cid",
                            "public_ip",
                            "ip_lat",
                            "ip_lng",
                            "ip_country",
                            "ip_region",
                            "ip_city",
                            "cert",
                            "brand",
                            "device",
                            "model",
                            "abi",
                            "version",
                            "sdk",
                            "hardware",
                            "board",
                            "register_time",
                            "last_heartbeat_time",
                            "state"))
        d["gateway_port"] = int(os.environ["API_PORT"])
        return d
    def get(self, domain):
        _, d = self.get_login_user_device(domain)
        self.tell(self.to_dict(d))
    def remove_direct(self, d):
        r = r_string(8)
        with session_scope() as session:
            d = session.query(Device).filter(Device.id == d.id).first()
            d.is_deleted = True
            d.service_port = 0
            d.token_id = f"deleted-{r}-{d.token_id}"
            d.dev_id = f"deleted-{r}-{d.dev_id}"
        remove_cert(certdir, d.domain)
        return None
    def remove_forward(self, d):
        r = r_string(8)
        with session_scope() as session:
            d = session.query(Device).filter(Device.id == d.id).first()
            d.is_deleted = True
            d.service_port = 0
            d.token_id = f"deleted-{r}-{d.token_id}"
            d.dev_id = f"deleted-{r}-{d.dev_id}"
        remove_cert(certdir, d.domain)
        return None
    def remove_p2p(self, d):
        res = self.ctl.deleteNode(d.token_id)
        r = r_string(8)
        with session_scope() as session:
            d = session.query(Device).filter(Device.id == d.id).first()
            d.is_deleted = True
            d.service_port = 0
            d.token_id = f"deleted-{r}-{d.token_id}"
            d.dev_id = f"deleted-{r}-{d.dev_id}"
        remove_cert(certdir, d.domain)
        return res
    def remove(self, domain):
        user = self.get_login_user_admin()
        _, d = self.get_login_user_device(domain, user=user)
        return getattr(self, f"remove_{d.mode}")(d)
    async def delete(self, domain):
        res = await self.call_sync_async(self.remove,
                                domain)
        self.tell(res)


class PlatformSpecificDeviceCommentHandler(BaseHttpService):
    def put(self, domain):
        user = self.get_login_user_admin()
        _, d = self.get_login_user_device(domain, user=user)
        comment = self.get_argument("comment")
        with session_scope() as session:
            session.query(Device).filter(Device.id == d.id).update(
                dict(comment=comment), synchronize_session=False
            )
        self.tell(None, status=0)


class PlatformDeviceStatsHandler(BaseHttpService):
    def to_dict(self, r):
        return r.to_dict(only=("batt_temperature",
                               "batt_percent",
                               "core_temperature",
                               "cpu_percent",
                               "cpu_freq_current",
                               "cpu_freq_max",
                               "cpu_freq_min",
                               "cpu_times_user",
                               "cpu_times_system",
                               "cpu_times_idle",
                               "disk_used",
                               "disk_free",
                               "disk_percent",
                               "disk_io_read_bytes",
                               "disk_io_read_count",
                               "disk_io_write_bytes",
                               "disk_io_write_count",
                               "disk_io_read_time",
                               "disk_io_write_time",
                               "disk_io_busy_time",
                               "net_io_bytes_sent",
                               "net_io_packets_sent",
                               "net_io_bytes_recv",
                               "net_io_packets_recv",
                               "mem_available",
                               "mem_percent",
                               "mem_used",
                               "mem_free",
                               "mem_active",
                               "mem_inactive",
                               "mem_buffers",
                               "mem_cached",
                               "mem_shared",
                               "mem_slab",
                               "process_count",
                               "thread_count",
                               "fd_count",
                               "crash_count",
                               "udpcon_count",
                               "tcpcon_count",
                               "wlan_linkspeed",
                               "wlan_freq",
                               "wlan_rssi",
                               "timestamp"))
    def get(self, domain):
        limit = self.get_argument("limit", 60, type=int)
        with session_scope() as session:
            _, d = self.get_login_user_device(domain, session=session)
            items = d.status.order_by(DeviceStatus.timestamp.desc()
                                                            ).limit(limit)
            res = [self.to_dict(i) for i in items]
        data = {}
        data["total"]   = len(res)
        data["data"]    = res
        self.tell(data)


class PlatformDeviceAllocHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(only=("id",
                                  "name",
                                  "contact",
                                  "last_login_ip",
                                  "register_time",
                                  "last_login_time",
                                  "is_admin"))
    def get(self, domain):
        sort = getattr(User,
                       self.get_argument("sort", "id"),
                                                        User.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        with session_scope() as session:
            _, device = self.get_login_user_device(domain, session=session)
            sel = session.query(User).join(UserDevice).filter(
                            UserDevice.device_id==device.id)
            items = qpaginate(sel.order_by(sort), page, size)
            total = sel.count()
        data = {}
        data["page"] = page
        data["size"] = size
        users = [self.to_dict(i) for i in items]
        data["total"] = total
        data["data"]  = users
        self.tell(data)
    def delete(self, domain):
        uid = self.get_argument("id")
        _ = self.get_login_user_admin()
        user = self.get_normal_user_by_id(uid)
        r = self.remove_device_from_user(domain, user)
        self.tell(None, status=int(not r))
    def post(self, domain):
        uid = self.get_argument("id")
        _ = self.get_login_user_admin()
        user = self.get_normal_user_by_id(uid)
        self.alloc_device_to_user(domain, user)
        self.tell(None, status=0)


class PlatformDeviceHandler(BaseHttpService):
    def get_super_key(self, domain):
        text = self.application.settings["sid"]
        key = sha256((text + domain).encode()).hexdigest()[::2]
        return key
    def to_dict(self, r):
        return r.to_dict(only=("domain",
                               "token_id",
                               "dev_id",
                               "comment",
                               "mode",
                               "boot_time",
                               "disk_total",
                               "disk_percent",
                               "mem_total",
                               "mem_percent",
                               "cpu_count",
                               "batt_charging",
                               "api_available",
                               "locked",
                               "controlling",
                               "brand",
                               "device",
                               "model",
                               "auth_token",
                               "cert",
                               "abi",
                               "version",
                               "sdk",
                               "hardware",
                               "board",
                               "register_time",
                               "last_heartbeat_time",
                               "batt_percent",
                               "state"))
    def create(self):
        now = datetime.now()
        table = string.octdigits + string.ascii_lowercase
        Y = table[now.year % len(table)]
        M = table[now.month]
        D = table[now.day]
        domain = f"u{Y}{M}{D}" + r_string(8)
        user = self.get_login_user_admin()
        mode = self.get_argument("mode")
        return getattr(self, f"create_{mode}")(domain, user)
    @ignore_exception(None)
    def link_device(self, ip, port, config):
        d = GrpcDevice(ip, port=port)
        uuid = d.server_info().uniqueId
        r = requests.post(f"http://{ip}:{port}/variables/pigeon", json=config)
        r.raise_for_status()
        d.reload(True)
        return uuid
    @ignore_exception(None)
    def check(self, address, port):
        with socket.socket() as sock:
            sock.settimeout(3.0)
            sock.connect((address, port))
            return address
    def create_scan(self, domain, user):
        port = self.get_argument("port", type=int)
        ip_start = self.get_argument("ip_start", type=str)
        ip_end = self.get_argument("ip_end", type=str)
        s = int(ipaddress.ip_address(ip_start))
        e = int(ipaddress.ip_address(ip_end))
        l = [str(ipaddress.ip_address(i)) for i in range(s, e + 1)]
        with ThreadPoolExecutor(32) as executor:
            futures = [executor.submit(self.check, i, port) for i in l]
            results = [f.result() for f in as_completed(futures)]
        result = [dict(ip=i, port=port) for i in \
                        results if i is not None]
        return result
    def create_direct(self, domain, user):
        auth, cert = generate_client_pem(domain)
        comment = self.get_argument("comment", "")
        port = self.get_argument("port", type=int)
        ip = self.get_argument("ip")

        cfg = dict()
        server = os.environ["LOCAL_LAN_IP"]
        cfg["properties.ckey"]  = self.application.settings["sapi_ckey"]
        cfg["properties.remote"] = f"http://{server}:{os.environ['WEB_PORT']}/properties/{domain}"
        cfg["properties.tries"]  = "64"

        dev_id = self.link_device(ip, port, cfg)
        dev_id or self.throw(410, "D3004", message="Cannot connect to device")

        res = {}
        res["domain"]            = domain
        res["cert"]              = cert.decode()
        res["dev_id"]            = dev_id
        res["comment"]           = comment
        res["auth_token"]        = auth
        res["mode"]              = DeviceMode.DIRECT.value
        res["token_id"]          = "r" + r_string(20)
        with session_scope() as session:
            user = self.get_user_by_id(user.id, session=session)
            device = Device(**res)
            session.add(device)
            session.flush()
            self.alloc_device_to_user(domain, user, session=session)
        save_cert(certdir, device.domain, device.cert)
        return self.to_dict(device)
    def create_forward(self, domain, user):
        auth, cert = generate_client_pem(domain)
        comment = self.get_argument("comment", "")

        res = {}
        res["domain"]            = domain
        res["cert"]              = cert.decode()
        res["dev_id"]            = None
        res["comment"]           = comment
        res["auth_token"]        = auth
        res["mode"]              = DeviceMode.FORWARD.value
        res["token_id"]          = "r" + r_string(20)
        with session_scope() as session:
            user = self.get_user_by_id(user.id, session=session)
            device = Device(**res)
            session.add(device)
            session.flush()
            self.alloc_device_to_user(domain, user, session=session)
        save_cert(certdir, device.domain, device.cert)
        return self.to_dict(device)
    def create_p2p(self, domain, user):
        if Config.get("top_available") != "true":
            self.throw(400, "D3005", message="P2P bridge not configured")
        auth, cert = generate_client_pem(domain)
        comment = self.get_argument("comment", None)
        meta = self.ctl.createNode(comment=domain)
        token = meta["data"]["token"]
        cfg = dict()
        evt = "device/${device_id}/event"
        cmd = "device/${device_id}/command"
        did = "${device_id}"
        server = self.application.settings["top_server"]
        key, crt, ca = Pem.parse(cert.decode())
        key = b64encode(key.as_bytes()).decode()
        crt = b64encode(crt.as_bytes()).decode()
        ca  = b64encode(ca .as_bytes()).decode()
        cfg["port"] = str(random.randint(40000, 60000))
        cfg["event"] = f"mqtts://{did}:{domain}.{token}@{server}/{evt}?command={cmd}&will={evt}&ca={ca}&key={key}&cert={crt}&qos=2&qsize=8192&keepalive=180&max_inflight_messages=20&session_expiry_interval=600&clean_start=false&encode=msgpack/zstd"
        cfg["cert"] = b64encode(cert).decode()
        cfg["ssl-web-credential"] = self.get_super_key(domain)
        cfg["task.concurrent"] = "true"
        cfg["task.heartbeat"] = "10"
        try:
            self.ctl.putNodeConfig(token, **cfg)
            self.ctl.setNodeStaticIp(token, "random",
                                                "random")
        except Exception as exc:
            self.ctl.deleteNode(token)
            raise exc
        res = {}
        res["domain"]            = domain
        res["cert"]              = cert.decode()
        res["token_id"]          = token
        res["comment"]           = comment
        res["auth_token"]        = auth
        res["mode"]              = DeviceMode.P2P.value
        with session_scope() as session:
            user = self.get_user_by_id(user.id, session=session)
            device = Device(**res)
            session.add(device)
            session.flush()
            self.alloc_device_to_user(domain, user, session=session)
        save_cert(certdir, device.domain, device.cert)
        return self.to_dict(device)
    async def post(self):
        res = await self.call_sync_async(self.create)
        self.tell(res)
    def get(self, *args):
        sort = getattr(Device,
                       self.get_argument("sort", "id"),
                                                        Device.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Device)
        with session_scope() as session:
            where = session.query(Device).filter(Device.is_deleted==False)
            if filtor: where = where.filter(*filtor)
            user = self.get_login_user(session=session)
            sel = where.join(UserDevice).filter(
                                    UserDevice.user_id==user.id)
            items = qpaginate(sel.order_by(sort), page, size)
            total = sel.count()
        data = {}
        data["page"] = page
        data["size"] = size
        devices = [self.to_dict(i) for i in items]
        data["total"] = total
        data["data"] = devices
        self.tell(data)


class PlatformUserLoginHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(only=("id",
                                  "name",
                                  "contact",
                                  "token",
                                  "last_login_ip",
                                  "register_time",
                                  "last_login_time",
                                  "is_admin"))
    def get(self):
        u = self.get_login_user()
        self.tell(self.to_dict(u))
    def post(self):
        name = self.get_argument("name")
        passwd = self.get_argument("password")
        with session_scope() as session:
            u = self.get_user_with_password(name, passwd, session=session)
            u.last_login_ip = self.request.remote_ip
            u.last_login_time = time.time()
        self.set_secure_cookie("token", u.name)
        self.tell(self.to_dict(u))
    def delete(self):
        self.clear_cookie("token")
        self.tell(None)


class PlatformUserHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(only=("id",
                                  "name",
                                  "contact",
                                  "last_login_ip",
                                  "register_time",
                                  "last_login_time",
                                  "is_admin"))
    def to_dict_mini(self, user):
        return user.to_dict(only=("id",
                                  "name",
                                  "is_admin"))
    def get(self):
        sort = getattr(User,
                       self.get_argument("sort", "id"),
                                                        User.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(User)
        with session_scope() as session:
            u = self.get_login_user(session=session)
            where = session.query(User)
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
        data = {}
        data["page"] = page
        data["size"] = size
        to_dict = self.to_dict if u.is_admin else self.to_dict_mini
        users = [to_dict(i) for i in items]
        data["total"] = total
        data["data"]  = users
        self.tell(data)
    def post(self):
        u = self.get_login_user_admin()
        name = self.get_argument("name")
        password = self.get_argument("password")
        contact = self.get_argument("contact", None)
        u = self.create_user(name, contact, password=password)
        self.tell(self.to_dict(u))


class PlatformSpecificUserHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(only=("id",
                                  "name",
                                  "contact",
                                  "last_login_ip",
                                  "register_time",
                                  "last_login_time",
                                  "is_admin"))
    def get(self, uid):
        u = self.get_user_admin_or_self(uid)
        self.tell(self.to_dict(u))
    def delete(self, uid):
        m = self.get_login_user()
        u = self.get_user_admin_or_self(uid)
        u.id == m.id and self.throw(400, "U2005", message="Unable to operate this user")
        with session_scope() as session:
            u = self.get_user_by_id(uid, session=session)
            session.delete(u)
        self.tell(None, status=0)


class PlatformSpecificUserCredHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(only=("id",
                                  "name",
                                  "contact",
                                  "last_login_ip",
                                  "register_time",
                                  "last_login_time",
                                  "is_admin"))
    def put(self, uid):
        user = self.get_user_admin_or_self(uid)
        password = self.get_argument("password")
        contact = self.get_argument("contact", None)
        with session_scope() as session:
            u = self.get_user_by_id(user.id, session=session)
            u.contact = contact if contact else u.contact
            u.password = password
        self.tell(self.to_dict(u))


class PlatformSpecificScriptHandler(BaseHttpService):
    def post(self, id):
        version = self.get_argument("version")
        change_log = self.get_argument("change_log", "")
        code = self.get_argument("code")
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, script = self.get_login_user_script_owner(id, user, session=session)
            stmt = pg_insert(ScriptVersion).values(parent_id=script.id,
                                                   version=version,
                                                   change_log=change_log,
                                                   code=code)
            stmt = stmt.on_conflict_do_nothing(index_elements=[ScriptVersion.parent_id, ScriptVersion.version]).returning(ScriptVersion.id)
            row = session.execute(stmt).first()
        row or self.throw(400, "V4102", message="Script version already exists")
        with session_scope() as session:
            version = session.query(ScriptVersion).filter(ScriptVersion.id==row.id).first()
        self.tell(version.to_dict(only=("id",
                                        "version",
                                        "change_log",
                                        "code",
                                        "parent_id",
                                        "create_time")))
    def delete(self, id):
        user = self.get_login_user()
        _, script = self.get_login_user_script_owner(id, user)
        with session_scope() as session:
            session.query(Script).filter(Script.id == script.id).update(
                dict(is_deleted=True), synchronize_session=False
            )
        self.tell(None, status=0)
    def to_dict(self, script, *extras):
        return script.to_dict(only=("name",
                                    "description",
                                    "type",
                                    "entry",
                                    "create_time",
                                    "versions.id",
                                    "versions.version",
                                    "versions.change_log",
                                    "versions.create_time",
                                    "owner.id",
                                    "owner.name",
                                    "owner.contact",
                                    "owner.is_admin",
                                    *tuple(item.key for item in extras if hasattr(item, "key"))))
    def get(self, id):
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, script = self.get_login_user_script(id, user=user, session=session)
            data = self.to_dict(script)
        self.tell(data)


class PlatformSpecificScriptVersionHandler(BaseHttpService):
    def get(self, id, ver):
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, version = self.get_login_user_script_version(id, ver, user=user, session=session)
            own = version.parent.owner.id == user.id
            data = version.to_dict(only=("id",
                                         "version",
                                         "change_log",
                                         "create_time",
                                         *(() if not own else ("code",))))
        self.tell(data)


class PlatformScriptAllocHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(only=("id",
                                  "name",
                                  "contact",
                                  "last_login_ip",
                                  "register_time",
                                  "last_login_time",
                                  "is_admin"))
    def get(self, id):
        sort = getattr(User,
                       self.get_argument("sort", "id"),
                                                        User.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        with session_scope() as session:
            _, script = self.get_login_user_script(id, session=session)
            sel = session.query(User).join(UserScript).filter(
                            UserScript.script_id==script.id)
            items = qpaginate(sel.order_by(sort), page, size)
            total = sel.count()
        data = {}
        data["page"] = page
        data["size"] = size
        users = [self.to_dict(i) for i in items]
        data["total"] = total
        data["data"]  = users
        self.tell(data)
    def delete(self, id):
        uid = self.get_argument("id")
        user = self.get_login_user()
        owner, _ = self.get_login_user_script_owner(id, user)
        user = self.get_user_by_id(uid)
        user.id == owner.id and self.throw(400, "U2005", message="Unable to operate this user")
        r = self.remove_script_from_user(id, user)
        self.tell(None, status=int(not r))
    def post(self, id):
        uid = self.get_argument("id")
        user = self.get_login_user()
        owner, _ = self.get_login_user_script_owner(id, user)
        user = self.get_user_by_id(uid)
        user.id == owner.id and self.throw(400, "U2005", message="Unable to operate this user")
        self.alloc_script_to_user(id, user)
        self.tell(None, status=0)


class PlatformScriptHandler(BaseHttpService):
    def to_dict(self, script):
        return script.to_dict(only=("id",
                                    "name",
                                    "description",
                                    "type",
                                    "entry",
                                    "create_time",
                                    "is_deleted",
                                    "owner.id",
                                    "owner.name"))
    def post(self):
        user = self.get_login_user()
        name = self.get_argument("name")
        description = self.get_argument("description", "")
        type = self.get_argument("type", type=int)
        params = self.get_argument("params", "[]", type=json.loads)
        entry = dict(method=self.get_argument("entry"),
                     params=params)
        with session_scope() as session:
            user = self.get_user_by_id(user.id, session=session)
            stmt = pg_insert(Script).values(owner_id=user.id,
                                            name=name,
                                            description=description,
                                            entry=entry,
                                            type=type)
            stmt = stmt.on_conflict_do_nothing(index_elements=[Script.name]).returning(Script.id)
            row = session.execute(stmt).first()
        row or self.throw(400, "S4003", message="Script already exists")
        with session_scope() as session:
            script = session.query(Script).filter(Script.id==row.id).first()
            user = self.get_user_by_id(user.id, session=session)
            self.alloc_script_to_user(script.id, user, session=session)
            data = self.to_dict(script)
        self.tell(data)
    def get(self, *args):
        sort = getattr(Script,
                       self.get_argument("sort", "id"),
                                                        Script.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Script)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            where = session.query(Script)
            if filtor: where = where.filter(*filtor)
            where = where.filter(Script.is_deleted==False)
            sel = where.join(UserScript).filter(
                                    UserScript.user_id==user.id)
            items = qpaginate(sel.order_by(sort), page, size)
            total = sel.count()
            scripts = [self.to_dict(i) for i in items]
        data = {}
        data["page"] = page
        data["size"] = size
        data["total"] = total
        data["data"] = scripts
        self.tell(data)


class PlatformSpecificDeviceJobHandler(BaseHttpService):
    def _callback_continue(self, job_id):
        with session_scope() as session:
            job = session.query(Job).filter(Job.id == job_id).first()
            if job.stop_time > 0 or job.state == JobState.STOPPED.value:
                self.throw(400, "J7003", message="Stopped job cannot be resumed")
            session.query(Job).filter(Job.id == job.id).update(dict(state=JobState.RUNNING.value), synchronize_session=False)
            session.query(DeviceJob).filter(DeviceJob.job_id==job.id).update(dict(state=DeviceJobState.INITIAL.value,
                             error=None), synchronize_session=False)

    def _callback_pause(self, job_id):
        with session_scope() as session:
            job = session.query(Job).filter(Job.id == job_id).first()
            if job.stop_time > 0 or job.state == JobState.STOPPED.value:
                self.throw(400, "J7004", message="Stopped job cannot be paused")
            session.query(Job).filter(Job.id == job.id).update(dict(state=JobState.PAUSED.value), synchronize_session=False)
            session.query(DeviceJob).filter(DeviceJob.job_id==job.id).update(dict(state=DeviceJobState.INITIAL.value,
                             error=None), synchronize_session=False)

    def _callback_stop(self, job_id):
        with session_scope() as session:
            job = session.query(Job).filter(Job.id == job_id).first()
            stop(session, job, with_running=True)

    def _callback_default(self, job_id):
        self.throw(400, "J7002", message="Invalid job state")

    def to_dict(self, job):
        return job.to_dict(only=("id",
                                 "name",
                                 "description",
                                 "config",
                                 "priority",
                                 "params",
                                 "param_source",
                                 "mode",
                                 "interval",
                                 "crontab",
                                 "count",
                                 "issued",
                                 "success",
                                 "failed",
                                 "timeout",
                                 "revoked",
                                 "create_time",
                                 "start_time",
                                 "stop_time",
                                 "state",
                                 "group.id",
                                 "group.name",
                                 "group.description",
                                 "group.color",
                                 "owner.id",
                                 "owner.name",
                                 "owner.contact",
                                 "script.id",
                                 "script.version",
                                 "script.change_log",
                                 "script.create_time",
                                 "script.parent.id",
                                 "script.parent.name",
                                 "script.parent.description",
                                 "script.parent.entry",
                                 "script.parent.create_time"))
    def get(self, task):
        with session_scope() as session:
            _, job = self.get_login_user_job_owner(task, session=session)
            data = self.to_dict(job)
        self.tell(data)
    def post(self, task):
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, job = self.get_login_user_job_owner(task, user=user, session=session)
            job_id = job.id
        state = self.get_argument("state", default="", type=str).strip().lower()
        handler = getattr(self, f"_callback_{state}", self._callback_default)
        handler(job_id)
        with session_scope() as session:
            job = session.query(Job).filter(Job.id==job_id).first()
            data = self.to_dict(job)
        self.tell(data)


class PlatformSpecificJobScriptVersionHandler(BaseHttpService):
    def post(self, task):
        script_version_id = self.get_argument("script_version_id", type=int)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, job = self.get_login_user_job_owner(task, user=user, session=session)
            if job.state == JobState.STOPPED.value:
                self.throw(400, "J7005", message="Stopped job cannot switch script version")
            _, version = self.get_login_user_script_version(job.script.parent_id,
                                                            script_version_id,
                                                            user=user,
                                                            session=session)
            job.script = version
            session.query(DeviceJob).filter(DeviceJob.job_id==job.id).update(dict(state=DeviceJobState.INITIAL.value,
                             error=None), synchronize_session=False)
            data = job.to_dict(only=("id",
                                     "name",
                                     "description",
                                     "config",
                                     "priority",
                                     "params",
                                     "param_source",
                                     "mode",
                                     "interval",
                                     "crontab",
                                     "count",
                                     "issued",
                                     "success",
                                     "failed",
                                     "timeout",
                                     "revoked",
                                     "create_time",
                                     "start_time",
                                     "stop_time",
                                     "state",
                                     "owner.id",
                                     "owner.name",
                                     "script.id",
                                     "script.version",
                                     "script.parent.id",
                                     "script.parent.name",
                                     "script.parent.description",
                                     "script.parent.type",
                                     "script.parent.create_time"))
        self.tell(data)


class PlatformJobHandler(BaseHttpService):
    def to_dict(self, job):
        return job.to_dict(only=("id",
                                 "name",
                                 "description",
                                 "config",
                                 "priority",
                                 "params",
                                 "param_source",
                                 "mode",
                                 "interval",
                                 "crontab",
                                 "count",
                                 "issued",
                                 "success",
                                 "failed",
                                 "timeout",
                                 "revoked",
                                 "create_time",
                                 "start_time",
                                 "stop_time",
                                 "state",
                                 "owner.id",
                                 "owner.name",
                                 "script.id",
                                 "script.version",
                                 "script.parent.id",
                                 "script.parent.name",
                                 "script.parent.description",
                                 "script.parent.type",
                                 "script.parent.create_time"))
    def post(self):
        name = self.get_argument("name")
        description = self.get_argument("description", "")
        s = self.get_argument("script_id", type=int)
        v = self.get_argument("script_version_id", type=int)
        g = self.get_argument("group_id", type=int)
        m = self.get_argument("model_id", type=int, default=-1)
        priority = self.get_argument("priority", default=50, type=int)
        interval = self.get_argument("interval", default=0, type=int)
        crontab = self.get_argument("crontab", default="", type=str).strip()
        param_source = self.get_argument("param_source", default=ParamSource.NATIVE.value)
        mode = self.get_argument("mode")
        count = self.get_argument("count", type=int)
        retries = self.get_argument("retries", type=int)
        time_limit = self.get_argument("time_limit", type=int)
        soft_time_limit = self.get_argument("soft_time_limit", type=int)
        is_foreground = self.get_argument("foreground", default=1, type=bool)
        ignore_result = self.get_argument("ignore_result", type=int)
        params = self.get_argument("params", type=json.loads)
        user = self.get_login_user()
        _, script = self.get_login_user_script_version(s, v, user=user)
        _, group = self.get_login_user_group(g, user=user)
        res = {}
        res["owner_id"]          = user.id
        res["group_id"]          = group.id
        res["script_id"]         = script.id
        res["name"]              = name
        res["description"]       = description
        res["priority"]          = priority
        model = None
        if m != -1: _, model = self.get_login_user_model(m, user=user)
        res["model_id"]          = model.id if model else None
        res["params"]            = params
        res["mode"]              = mode
        res["count"]             = count
        res["interval"]          = interval
        res["crontab"]           = crontab
        res["param_source"]      = param_source

        config = dict()
        config["retries"] = retries
        config["time_limit"] = time_limit
        config["soft_time_limit"] = soft_time_limit
        config["ignore_result"] = bool(ignore_result)
        config["mutex"] = "foreground" if is_foreground else None

        res["start_time"]        = int(time.time())
        res["stop_time"]         = 0
        res["state"]             = JobState.RUNNING.value
        res["config"]            = config
        res["issued"]            = 0
        res["success"]           = 0
        res["failed"]            = 0
        res["timeout"]           = 0
        res["revoked"]           = 0
        with session_scope() as session:
            job = Job(**res)
            session.add(job)
            session.flush()
            data = self.to_dict(job)
        sync.apply_async()
        self.tell(data)
    def get(self):
        sort = getattr(Job,
                       self.get_argument("sort", "id"),
                                                        Job.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Job)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            where = session.query(Job).filter(Job.owner_id==user.id)
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
            tasks = [self.to_dict(i) for i in items]
        data = {}
        data["page"] = page
        data["size"] = size
        data["total"] = total
        data["data"] = tasks
        self.tell(data)


class PlatformJobDeviceTabHandler(BaseHttpService):
    def get(self, task):
        sort = getattr(Device,
                       self.get_argument("sort", "id"),
                                                        Device.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Device)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, job = self.get_login_user_job_owner(task, user=user, session=session)
            where = session.query(DeviceJob).join(Device).filter(DeviceJob.job_id==job.id)
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
            djs = [link.to_dict(only=("state",
                                      "binding_state",
                                      "create_time",
                                      "leave_time",
                                      "issued",
                                      "cooldown",
                                      "success",
                                      "failed",
                                      "revoked",
                                      "timeout",
                                      "error",
                                      "device.domain",
                                      "device.token_id",
                                      "device.comment",
                                      "device.boot_time",
                                      "device.disk_total",
                                      "device.mem_percent",
                                      "device.disk_percent",
                                      "device.mem_used",
                                      "device.disk_used",
                                      "device.mem_total",
                                      "device.cpu_count",
                                      "device.batt_charging",
                                      "device.api_available",
                                      "device.locked",
                                      "device.controlling",
                                      "device.brand",
                                      "device.device",
                                      "device.model",
                                      "device.abi",
                                      "device.version",
                                      "device.sdk",
                                      "device.hardware",
                                      "device.board",
                                      "device.register_time",
                                      "device.state")) for link in items]
        data = {}
        data["page"] = page
        data["size"] = size
        data["total"] = total
        data["data"] = djs
        self.tell(data)


class PlatformSpecificJobTaskListHandler(BaseHttpService):
    def to_dict(self, execution):
        return execution.to_dict(only=("id",
                                       "task_id",
                                       "state",
                                       "reason",
                                       "elapsed_time",
                                       "start_time",
                                       "finish_time",
                                       "create_time",
                                       "device.id",
                                       "device.domain",
                                       "device.state"))
    def get(self, task):
        sort = getattr(Device,
                       self.get_argument("sort", "id"),
                                                        Task.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Task)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, job = self.get_login_user_job_owner(task, user=user, session=session)
            where = session.query(Task).join(Device).filter(Task.job_id==job.id)
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
            data_rows = [self.to_dict(i) for i in items]
        data = {}
        data["page"] = page
        data["size"] = size
        data["total"] = total
        data["data"] = data_rows
        self.tell(data)
    def delete(self, task):
        with_running = self.get_argument("with_running", type=bool)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, job = self.get_login_user_job_owner(task, user=user, session=session)
            stop(session, job, with_running=with_running)
        self.tell(None, status=0)


class PlatformSpecificJobTaskInfoHandler(BaseHttpService):
    def to_dict(self, execution):
        return execution.to_dict(only=("id",
                                       "task_id",
                                       "params",
                                       "result",
                                       "exception",
                                       "traceback",
                                       "state",
                                       "reason",
                                       "start_time",
                                       "elapsed_time",
                                       "finish_time",
                                       "create_time",
                                       "resources.id",
                                       "resources.type",
                                       "resources.name",
                                       "resources.data",
                                       "resources.create_time",
                                       "device.id",
                                       "device.domain",
                                       "device.dev_id",
                                       "device.state",
                                       "script.id",
                                       "script.version",
                                       "script.change_log",
                                       "script.parent.id",
                                       "script.parent.name",
                                       "script.parent.description",
                                       "script.parent.type",
                                       "script.parent.entry",
                                       "script.parent.create_time",
                                       "job.id",
                                       "job.name",
                                       "job.description",
                                       "job.config",
                                       "job.priority",
                                       "job.params",
                                       "job.mode",
                                       "job.count",
                                       "job.create_time"))
    def get(self, task, exec):
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, job = self.get_login_user_job_owner(task, user=user, session=session)
            execution = session.query(Task).filter(Task.job_id==job.id, Task.id==int(exec)).first()
            data = self.to_dict(execution) if execution else None
        if not execution: self.throw(401, "T5001", message="Task execution does not exist")
        self.tell(data)


class PlatformTaskQueueTokenAuthHandler(BaseHttpService):
    def get_queue_job(self, session, job_id, token, with_running=True):
        job = session.query(Job).filter(Job.id==int(job_id)).first()
        if not job: self.throw(401, "J7006", message="The job does not exist")
        if job.param_source != ParamSource.QUEUE.value or job.params.get("token") != token:
            self.throw(400, "J7007", message="Incorrect key or this task is not in queue mode")
        if with_running and (job.stop_time > 0 or job.state != JobState.RUNNING.value):
            self.throw(400, "J7008", message="The job is not in a running state")
        return job
    def check_domain(self, job_id, domain):
        with session_scope() as session:
            d = self.get_device_by_domain(domain, session=session)
            dt = session.query(DeviceJob).filter(DeviceJob.device_id==d.id, DeviceJob.job_id==job_id).first()
            if not dt or dt.binding_state != DeviceJobBindingState.ACTIVE.value: self.throw(400, "J7009", message="The specified device is not bound to this job")
            if dt.state != DeviceJobState.PREPARED.value: self.throw(400, "J7010", message="The device is offline and cannot receive jobs")
            if d.state != DeviceState.ONLINE.value: self.throw(400, "J7011", message="The device is not prepared to receive the job")
    def prepare_request(self, job_id):
        domain = self.get_argument("domain", "")
        token = self.get_argument("token")
        with session_scope() as session:
            job = self.get_queue_job(session, job_id, token, with_running=True)
            if domain: self.check_domain(job.id, domain)
            self.wtq = WaitableTaskQueue(job)
            self.domain = domain or None


class PlatformTaskQueueDeviceListHandler(PlatformTaskQueueTokenAuthHandler):
    def get(self, job_id):
        sort = getattr(Device,
                       self.get_argument("sort", "id"),
                                                        Device.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Device)
        token = self.get_argument("token")
        with session_scope() as session:
            job = self.get_queue_job(session, job_id, token, with_running=True)
            where = session.query(DeviceJob).join(Device).filter(DeviceJob.job_id==job.id)
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
            djs = [link.to_dict(only=("state",
                                      "binding_state",
                                      "create_time",
                                      "leave_time",
                                      "issued",
                                      "cooldown",
                                      "success",
                                      "failed",
                                      "revoked",
                                      "timeout",
                                      "error",
                                      "device.domain",
                                      "device.comment",
                                      "device.boot_time",
                                      "device.disk_total",
                                      "device.mem_percent",
                                      "device.disk_percent",
                                      "device.mem_used",
                                      "device.disk_used",
                                      "device.mem_total",
                                      "device.cpu_count",
                                      "device.batt_charging",
                                      "device.api_available",
                                      "device.locked",
                                      "device.controlling",
                                      "device.brand",
                                      "device.device",
                                      "device.model",
                                      "device.abi",
                                      "device.version",
                                      "device.sdk",
                                      "device.hardware",
                                      "device.board",
                                      "device.register_time",
                                      "device.state")) for link in items]
        data = {}
        data["page"] = page
        data["size"] = size
        data["total"] = total
        data["data"] = djs
        self.tell(data)


class PlatformTaskQueuePublishHandler(BaseHttpService):
    def get_queue_job(self, session, job_id, token, with_running=True):
        job = session.query(Job).filter(Job.id==int(job_id)).first()
        if not job: self.throw(401, "J7006", message="The job does not exist")
        if job.param_source != ParamSource.QUEUE.value or job.params.get("token") != token:
            self.throw(400, "J7007", message="Incorrect key or this task is not in queue mode")
        if with_running and (job.stop_time > 0 or job.state != JobState.RUNNING.value):
            self.throw(400, "J7008", message="The job is not in a running state")
        return job
    def check_domain(self, job_id, domain):
        with session_scope() as session:
            d = self.get_device_by_domain(domain, session=session)
            dt = session.query(DeviceJob).filter(DeviceJob.device_id==d.id, DeviceJob.job_id==job_id).first()
            if not dt or dt.binding_state != DeviceJobBindingState.ACTIVE.value: self.throw(400, "J7009", message="The specified device is not bound to this job")
            if dt.state != DeviceJobState.PREPARED.value: self.throw(400, "J7010", message="The device is offline and cannot receive jobs")
            if d.state != DeviceState.ONLINE.value: self.throw(400, "J7011", message="The device is not prepared to receive the job")
    def prepare_request(self, job_id):
        domain = self.get_argument("domain", "")
        token = self.get_argument("token")
        with session_scope() as session:
            job = self.get_queue_job(session, job_id, token, with_running=True)
            if domain: self.check_domain(job.id, domain)
            self.wtq = WaitableTaskQueue(job)
            self.domain = domain or None
    async def send_task(self, t):
        await self.wtq.send(t.get("params", {}), task_id=t.get("task_id", None),
                                                 domain=self.domain)
    async def put(self, job_id):
        self.prepare_request(job_id)
        tasks = json.loads(self.request.body)
        await asyncio.gather(*[self.send_task(t) for t in tasks])
        self.finish()
    def _wait_timeout(self):
        self.throw(408, "J7012", message="Timeout reached while waiting for result")
    async def post(self, job_id):
        self.prepare_request(job_id)
        timeout = self.get_argument("timeout", 120, type=int)
        task = json.loads(self.request.body)
        result = await self.wtq.wait(task.get("params", {}),
                                              task_id=task.get("task_id", None),
                                              domain=self.domain,
                                              throw=self._wait_timeout,
                                              timeout=timeout)
        self.finish(result)


class PlatformOverallJobTaskStatusHandler(BaseHttpService):
    def get(self):
        with session_scope() as session:
            user = self.get_login_user(session=session)
            minute = ((Task.create_time / 60) * 60).label("minute")
            query = (session.query(minute,
            fn.SUM(Case(None, [(Task.state==TaskState.FAILED.value,  1)], 0)).label("f"),
            fn.SUM(Case(None, [(Task.state==TaskState.SUCCESS.value, 1)], 0)).label("s"),
            fn.SUM(Case(None, [(Task.state==TaskState.TIMEOUT.value, 1)], 0)).label("t"),
            ).select_from(Task
            ).join(Job, Task.job_id==Job.id
            ).filter((Job.owner_id == user.id) & (Task.create_time >= (time.time() - 21600))
            ).group_by(minute
            ).order_by(minute))
            count = (session.query(
            fn.SUM(Case(None, [(Task.state==TaskState.FAILED.value,  1)], 0)).label("f"),
            fn.SUM(Case(None, [(Task.state==TaskState.SUCCESS.value, 1)], 0)).label("s"),
            fn.SUM(Case(None, [(Task.state==TaskState.TIMEOUT.value, 1)], 0)).label("t"),
            ).select_from(Task
            ).join(Job, Task.job_id==Job.id
            ).filter(Job.owner_id == user.id
            ).first())
            running = (session.query(Job)
                   .filter((Job.owner_id == user.id) &
                           (Job.state == JobState.RUNNING.value))
                   ).count()
            paused = (session.query(Job)
                   .filter((Job.owner_id == user.id) &
                           (Job.state == JobState.PAUSED.value))
                   ).count()
            line = [dict(success=int((r._mapping.get("s") or 0)),
                         timeout=int((r._mapping.get("t") or 0)),
                         failed=int((r._mapping.get("f") or 0)),
                         timestamp=int((r._mapping.get("minute") or 0))) for r in query.all()]
        count = count._mapping if count else {}
        self.tell(dict(trend=line, running=running, paused=paused,
                                failed=int((count.get("f") or 0)),
                                success=int((count.get("s") or 0)),
                                timeout=int((count.get("t") or 0))))


class PlatformGroupHandler(BaseHttpService):
    def to_dict(self, group):
        data = group.to_dict(only=("id",
                                   "name",
                                   "description",
                                   "order",
                                   "color",
                                   "create_time",
                                   "update_time"))
        data["total"] = group.devices.count()
        return data
    def get(self):
        sort = getattr(Group,
                       self.get_argument("sort", "order"),
                                                        Group.order)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Group)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            where = session.query(Group).filter(Group.owner_id==user.id)
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
            groups = [self.to_dict(i) for i in items]
        data = {}
        data["page"] = page
        data["size"] = size
        data["total"] = total
        data["data"] = groups
        self.tell(data)
    def post(self):
        user = self.get_login_user()
        name = self.get_argument("name")
        description = self.get_argument("description")
        color = self.get_argument("color")
        with session_scope() as session:
            user = self.get_user_by_id(user.id, session=session)
            stmt = pg_insert(Group).values(owner_id=user.id,
                                           name=name,
                                           description=description,
                                           color=color)
            stmt = stmt.on_conflict_do_nothing(index_elements=[Group.owner_id, Group.name]).returning(Group.id)
            row = session.execute(stmt).first()
        row or self.throw(400, "G6002", message="Group already exists")
        with session_scope() as session:
            group = session.query(Group).filter(Group.id==row.id).first()
            data = self.to_dict(group)
        self.tell(data)


class PlatformSpecificGroupHandler(BaseHttpService):
    def to_dict(self, group):
        return group.to_dict(only=("id",
                                   "name",
                                   "description",
                                   "order",
                                   "color",
                                   "create_time",
                                   "update_time"))
    def get(self, group):
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, group = self.get_login_user_group(group, user=user, session=session)
            data = self.to_dict(group)
            data["total"] = group.devices.count()
        self.tell(data)
    def delete(self, group):
        user = self.get_login_user()
        _, group = self.get_login_user_group(group)
        with session_scope() as session:
            group = session.query(Group).filter(Group.id == group.id).first()
            session.delete(group)
        sync.apply_async()
        self.tell(None)


class PlatformSpecificGroupDeviceHandler(BaseHttpService):
    def to_dict(self, r):
        return r.to_dict(only=("domain",
                               "token_id",
                               "dev_id",
                               "comment",
                               "boot_time",
                               "disk_total",
                               "disk_percent",
                               "mode",
                               "mem_total",
                               "mem_percent",
                               "cpu_count",
                               "batt_charging",
                               "api_available",
                               "locked",
                               "controlling",
                               "brand",
                               "device",
                               "model",
                               "abi",
                               "version",
                               "sdk",
                               "hardware",
                               "board",
                               "register_time",
                               "last_heartbeat_time",
                               "batt_percent",
                               "state"))
    def get(self, group):
        sort = getattr(Device,
                       self.get_argument("sort", "order"),
                                                        Device.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Device)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            _, group = self.get_login_user_group(group, user=user, session=session)
            where = group.devices
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
            devices = [self.to_dict(i) for i in items]
        data = {}
        data["page"] = page
        data["size"] = size
        data["total"] = total
        data["data"] = devices
        self.tell(data)
    def post(self, group):
        user = self.get_login_user()
        domains = self.get_argument("devices", "[]", type=json.loads)
        _, group = self.get_login_user_group(group, user=user)
        with session_scope() as session:
            ids = session.query(Device.id).filter(Device.domain.in_(domains))
            ids = ids.filter(Device.is_deleted==False)
            count = session.query(UserDevice).filter((UserDevice.user_id == user.id) &
                        (UserDevice.device_id.in_(ids))).update(dict(group_id=group.id), synchronize_session=False)
        sync.apply_async()
        self.tell(dict(total=count))
    def delete(self, group):
        user = self.get_login_user()
        domains = self.get_argument("devices", "[]", type=json.loads)
        _, group = self.get_login_user_group(group, user=user)
        with session_scope() as session:
            ids = session.query(Device.id).filter(Device.domain.in_(domains)).filter(Device.is_deleted==False)
            count = session.query(UserDevice).filter((UserDevice.user_id == user.id) &
                        (UserDevice.device_id.in_(ids))).update(dict(group_id=None), synchronize_session=False)
        sync.apply_async()
        self.tell(dict(total=count))


class PlatformUngroupedDeviceHandler(BaseHttpService):
    def to_dict(self, r):
        return r.to_dict(only=("domain",
                               "token_id",
                               "dev_id",
                               "comment",
                               "boot_time",
                               "disk_total",
                               "disk_percent",
                               "mode",
                               "mem_total",
                               "mem_percent",
                               "cpu_count",
                               "batt_charging",
                               "api_available",
                               "locked",
                               "controlling",
                               "brand",
                               "device",
                               "model",
                               "abi",
                               "version",
                               "sdk",
                               "hardware",
                               "board",
                               "register_time",
                               "last_heartbeat_time",
                               "batt_percent",
                               "state"))
    def get(self):
        sort = getattr(Device,
                       self.get_argument("sort", "order"),
                                                        Device.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Device)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            where = (session.query(Device).join(UserDevice).filter(
                        (UserDevice.user_id == user.id) &
                        (UserDevice.group_id.is_(None)) &
                        (Device.is_deleted==False)
            ))
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
        data = {}
        data["page"] = page
        data["size"] = size
        devices = [self.to_dict(i) for i in items]
        data["total"] = total
        data["data"] = devices
        self.tell(data)


class PlatformModelHandler(BaseHttpService):
    def to_dict(self, model):
        return model.to_dict(only=("id",
                                   "name",
                                   "description",
                                   "owner_id",
                                   "provider",
                                   "api_base",
                                   "api_key",
                                   "model_name",
                                   "vision_mode",
                                   "vision_scale",
                                   "step_delay",
                                   "max_completion_tokens",
                                   "temperature",
                                   "token_count",
                                   "create_time"))
    def post(self):
        name = self.get_argument("name")
        description = self.get_argument("description", "")
        provider = self.get_argument("provider", ModelProvider.OPENAI_COMPATIBLE.value)
        provider = str(provider or ModelProvider.OPENAI_COMPATIBLE.value).strip().lower().replace("-", "_")
        api_base = self.get_argument("api_base")
        model = self.get_argument("model")
        api_key = self.get_argument("api_key")
        vision = self.get_argument("mode", "") == "vision"
        scale = self.get_argument("scale", "0", type=int)
        temperature = self.get_argument("temperature", "0.0", type=float)
        step_delay = self.get_argument("step_delay", "0.0", type=float)
        max_completion_tokens = self.get_argument("max_completion_tokens", "4096", type=int)
        context_window = self.get_argument("context_window", 256*1024, type=int)
        user = self.get_login_user()
        with session_scope() as session:
            user = self.get_user_by_id(user.id, session=session)
            stmt = pg_insert(ModelResource).values(name=name,
                                                   description=description,
                                                   provider=provider,
                                                   api_base=api_base,
                                                   model_name=model,
                                                   api_key=api_key,
                                                   vision_mode=vision,
                                                   temperature=temperature,
                                                   max_completion_tokens=max_completion_tokens,
                                                   context_window=context_window,
                                                   step_delay=step_delay,
                                                   vision_scale=scale,
                                                   owner_id=user.id)
            stmt = stmt.on_conflict_do_nothing(index_elements=[ModelResource.name]).returning(ModelResource.id)
            row = session.execute(stmt).first()
        row or self.throw(400, "M8002", message="Model already exists")
        with session_scope() as session:
            model = session.query(ModelResource).filter(ModelResource.id==row.id).first()
        self.tell(self.to_dict(model))
    def get(self):
        sort = getattr(ModelResource,
                       self.get_argument("sort", "id"),
                                            ModelResource.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(ModelResource)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            where = session.query(ModelResource).filter(ModelResource.owner_id==user.id)
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
        data = {}
        data["page"] = page
        data["size"] = size
        models = [self.to_dict(i) for i in items]
        data["total"] = total
        data["data"] = models
        self.tell(data)


class PlatformDeviceIdleHandler(BaseHttpService):
    def to_dict(self, r):
        return r.to_dict(only=("domain",
                               "dev_id",
                               "comment",
                               "api_available",
                               "locked",
                               "brand",
                               "device",
                               "model",
                               "abi",
                               "version",
                               "sdk",
                               "hardware",
                               "board",
                               "register_time",
                               "last_heartbeat_time",
                               "state"))
    def get(self):
        sort = getattr(Device,
                       self.get_argument("sort", "id"),
                                                        Device.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = max(1, self.get_argument("page", 1, type=int))
        size = max(1, self.get_argument("size", 20, type=int))
        filtor = self.query_to_model_filter(Device)
        with session_scope() as session:
            user = self.get_login_user(session=session)
            running = (session.query(DeviceJob.device_id).join(Job).filter(
                                    (Job.state==JobState.RUNNING.value) &
                                    (DeviceJob.binding_state==DeviceJobBindingState.ACTIVE.value)))
            where = (session.query(Device).join(UserDevice).filter(
                                    (UserDevice.user_id==user.id) &
                                    (Device.state==DeviceState.ONLINE.value) &
                                    (Device.is_deleted==False) &
                                    (Device.id.notin_(running))))
            if filtor: where = where.filter(*filtor)
            items = qpaginate(where.order_by(sort), page, size)
            total = where.count()
        data = {}
        data["page"] = page
        data["size"] = size
        data["total"] = total
        data["data"] = [self.to_dict(i) for i in items]
        self.tell(data)


class PlatformSpecificModelHandler(BaseHttpService):
    def delete(self, model):
        user = self.get_login_user()
        _, model = self.get_login_user_model(model)
        with session_scope() as session:
            active = session.query(Job.id).filter(Job.model_id == model.id, Job.state != JobState.STOPPED.value).first()
            active and self.throw(400, "M8003", message="Model is referenced by non-stopped jobs")
            model = session.query(ModelResource).filter(ModelResource.id == model.id).first()
            session.delete(model)
        self.tell(None)


class PlatformConfigHandler(BaseHttpService):
    async def get(self):
        u = self.get_login_user_admin()

        data = dict()
        ip = os.environ["PUBLIC_IP"]
        data["public_ip"] = ip
        data["top_server"] = Config.get("top_server")
        data["web_port"] = os.environ["WEB_PORT"]
        data["sapi_ckey"] = Config.get("sapi_ckey")
        data["top_endpoint"] = Config.get("top_endpoint")
        data["top_ckey"] = Config.get("top_client_key")
        self.tell(data)


class Service(object):
    def __init__(self, port=8800):
        http = HttpServiceManager(port)
        # HEAD
        http.add_handler("/validate/([0-9a-z]+)", "server.service",
                        handler="PlatformValidateHandler")
        # PUT
        http.add_handler("/api/v1/device/([a-z0-9]+)/comment", "server.service",
                        handler="PlatformSpecificDeviceCommentHandler")
        # GET
        http.add_handler("/api/v1/device/idle", "server.service",
                        handler="PlatformDeviceIdleHandler")
        # GET, DELETE
        http.add_handler("/api/v1/device/([a-z0-9]+)", "server.service",
                        handler="PlatformSpecificDeviceHandler")
        # GET
        http.add_handler("/api/v1/device/([a-z0-9]+)/status", "server.service",
                        handler="PlatformDeviceStatsHandler")
        # GET, POST, DELETE
        http.add_handler("/api/v1/device/([a-z0-9]+)/alloc", "server.service",
                        handler="PlatformDeviceAllocHandler")
        # GET, POST
        http.add_handler("/api/v1/device", "server.service",
                        handler="PlatformDeviceHandler")
        # GET, POST
        http.add_handler("/api/v1/script", "server.service",
                        handler="PlatformScriptHandler")
        # GET, POST
        http.add_handler("/api/v1/group", "server.service",
                        handler="PlatformGroupHandler")
        # GET
        http.add_handler("/api/v1/ungrouped/devices", "server.service",
                        handler="PlatformUngroupedDeviceHandler")
        # GET POST DELETE
        http.add_handler("/api/v1/group/(\d+)/devices", "server.service",
                        handler="PlatformSpecificGroupDeviceHandler")
        # GET, DELETE
        http.add_handler("/api/v1/group/(\d+)", "server.service",
                        handler="PlatformSpecificGroupHandler")
        # GET, POST
        http.add_handler("/api/v1/model", "server.service",
                        handler="PlatformModelHandler")
        # DELETE
        http.add_handler("/api/v1/model/(\d+)", "server.service",
                        handler="PlatformSpecificModelHandler")
        http.add_handler("/api/v1/job/(\d+)/run/devices", "server.service",
                        handler="PlatformTaskQueueDeviceListHandler")
        http.add_handler("/api/v1/job/(\d+)/run", "server.service",
                        handler="PlatformTaskQueuePublishHandler")
        # GET, POST
        http.add_handler("/api/v1/job", "server.service",
                        handler="PlatformJobHandler")
        # GET
        http.add_handler("/api/v1/job/(\d+)/execute", "server.service",
                        handler="PlatformSpecificJobTaskListHandler")
        # GET, POST
        http.add_handler("/api/v1/job/(\d+)", "server.service",
                        handler="PlatformSpecificDeviceJobHandler")
        # PUT
        http.add_handler("/api/v1/job/(\d+)/script-version", "server.service",
                        handler="PlatformSpecificJobScriptVersionHandler")
        # GET, POST, DELETE
        http.add_handler("/api/v1/job/(\d+)/device", "server.service",
                        handler="PlatformJobDeviceTabHandler")
        # GET
        http.add_handler("/api/v1/job/(\d+)/execute/(\d+)", "server.service",
                        handler="PlatformSpecificJobTaskInfoHandler")
        # GET
        http.add_handler("/api/v1/job/status", "server.service",
                        handler="PlatformOverallJobTaskStatusHandler")
        # GET, DELETE, PUT
        http.add_handler("/api/v1/script/(\d+)", "server.service",
                        handler="PlatformSpecificScriptHandler")
        # GET
        http.add_handler("/api/v1/script/(\d+)/(\d+)", "server.service",
                        handler="PlatformSpecificScriptVersionHandler")
        # GET, POST, DELETE
        http.add_handler("/api/v1/script/(\d+)/alloc", "server.service",
                        handler="PlatformScriptAllocHandler")
        # GET
        http.add_handler("/api/v1/summary", "server.service",
                        handler="PlatformSummaryInfoHandler")
        # GET
        http.add_handler("/api/v1/platform/config", "server.service",
                        handler="PlatformConfigHandler")
        # GET, DELETE
        http.add_handler("/api/v1/user/(\d+)", "server.service",
                        handler="PlatformSpecificUserHandler")
        # PUT
        http.add_handler("/api/v1/user/(\d+)/credentials", "server.service",
                        handler="PlatformSpecificUserCredHandler")
        # GET, POST, DELETE
        http.add_handler("/api/v1/user/login", "server.service",
                        handler="PlatformUserLoginHandler")
        # GET, POST
        http.add_handler("/api/v1/user", "server.service",
                        handler="PlatformUserHandler")
        self.http = http
    def run(self):
        sid = Config.get("sid")
        top_server = Config.get("top_server")
        sapi_ckey = Config.get("sapi_ckey")
        endpoint = Config.get("top_endpoint")
        ckey = Config.get("top_client_key")

        kwargs = {}
        kwargs["cookie_secret"] = sid
        kwargs["ctl"] = TopNetworkCtl(sid, endpoint,
                                                   ckey)
        kwargs["top_server"] = top_server
        kwargs["sapi_ckey"] = sapi_ckey
        kwargs["sid"] = sid
        logger.setLevel(logging.DEBUG)
        self.http.start_server(**kwargs)
