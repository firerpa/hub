# Copyright 2022 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import os
import re
import time
import uuid
import json
import shlex
import random
import shutil
import logging
import platform
import psutil
import asyncio
import uvloop
import importlib
import subprocess
import tornado.web
import tornado.ioloop
import cachetools.func
import threading
import traceback
import redis

from ipaddress import ip_network
from hashlib import sha256
from base64 import b64encode
from collections import OrderedDict
from urllib.parse import urlparse
from collections import Counter
import datetime
from datetime import timezone

from tornado.ioloop import IOLoop
from tornado.options import define, options
from tornado.web import Application, HTTPError
from tornado.websocket import WebSocketHandler
from tornado.netutil import bind_unix_socket
from tornado.httpserver import HTTPServer
from concurrent.futures import ThreadPoolExecutor
from driver.bridge import TopClient

from . import __version__
from .top import *
from .models import *
from .event import EventConnectionService, certdir
from .utils import *

errors = {}
# platform
errors["E40101"] = "Unauthorized user"
errors["E40102"] = "Not a platform administrator user"
errors["E40103"] = "Not the device owner"
errors["E40005"] = "Target user cannot be an administrator"
errors["E40105"] = "Only administrators or owners can operate"
errors["E40401"] = "User does not exist"
errors["E40402"] = "Device does not exist"
errors["E40405"] = "No translation file for this language"
errors["E40001"] = "Invalid username or password"
errors["E40002"] = "The user already owns the device"
errors["E40003"] = "User already exists"
errors["E40004"] = "Unable to operate this user"
errors["E40017"] = "Invalid username"
errors["E50000"] = "Internal server error"
errors["E40000"] = "Bad request"
# ztnet
errors["E40403"] = "No such service token"
errors["E40404"] = "No such node token"
errors["E40006"] = "This token is bounded to another client"
errors["E40007"] = "Duplicate ip address"
errors["E40008"] = "The network address for this token is not set"
errors["E40009"] = "Maximum allowed nodes exceeded"
errors["E40010"] = "Network is not configured"
errors["E40011"] = "Invalid ip address"
errors["E40012"] = "Exceed max node config entries"
errors["E40013"] = "Unable to set configuration for attached node"
errors["E40014"] = "Value cannot contain spaces"
errors["E40015"] = "Network is already configured"
errors["E40016"] = "Network too small or invalid"
errors["E40018"] = "Network is disabled"

logger = logging.getLogger()
db = redis.StrictRedis.from_url("unix:///run/redis.sock")


class HttpServiceManager(object):
    def __init__(self, bind="/run/server.sock"):
        self.handlers = OrderedDict()
        pkg_dir = os.path.dirname(__file__)
        self.static = os.path.join(pkg_dir, "static")
        self.template = os.path.join(pkg_dir, "html")
        self.bind = bind

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
        socket = bind_unix_socket(self.bind, mode=0o666)
        server.add_socket(socket)
        self.ioloop.start()


class BaseHttpService(tornado.web.RequestHandler):
    def get_login_user(self):
        cname = self.get_secure_cookie("token")
        xname = self.request.headers.get("X-User", "")
        xauth = self.request.headers.get("X-Auth", "")

        user = User.get_or_none(User.name==cname)
        user = user or User.get_or_none((User.name==xname)
                                      & (User.token==xauth))
        user or self.throw(401, "E40101")
        return user

    def get_user_with_password(self, name,
                                    password):
        user = User.get_or_none((User.name==name)
                           & (User.password==password))
        user or self.throw(400, "E40001")
        return user

    def get_login_user_device(self, domain,
                                    user=None):
        _ = self.get_device_by_domain(domain)
        user = user or self.get_login_user()
        device = Device.select().join(UserDevice).where((UserDevice.user==user)
                                                      & (Device.domain==domain)
                                                       ).get_or_none()
        device or self.throw(401, "E40103")
        return user, device

    def get_login_user_admin(self):
        user = self.get_login_user()
        user.admin or self.throw(401, "E40102")
        return user

    def get_user_admin_or_self(self, uid):
        user = self.get_user_by_id(uid)
        c = self.get_login_user()
        check = (user.id != c.id and not c.admin)
        check and self.throw(401, "E40105")
        return user

    def remove_device_from_user(self, domain, user):
        user, device = self.get_login_user_device(domain, user=user)
        query = UserDevice.delete().where((UserDevice.user_id==user.id)
                                        & (UserDevice.device_id==device.id))
        return query.execute()

    def get_user_by_id(self, uid):
        user = User.get_or_none((User.id==uid) | (User.name==uid))
        user or self.throw(404, "E40401")
        return user

    def get_normal_user_by_id(self, uid):
        user = self.get_user_by_id(uid)
        user.admin and self.throw(401, "E40005")
        return user

    def get_device_by_domain(self, domain):
        device = Device.get_or_none(Device.domain==domain)
        device or self.throw(404, "E40402")
        return device

    def get_device_by_token(self, token):
        device = Device.get_or_none(Device.token_id==token)
        device or self.throw(404, "E40402")
        return device

    def alloc_device_to_user(self, domain, user):
        device = self.get_device_by_domain(domain)
        gd, created = UserDevice.get_or_create(user=user,
                                 device=device)
        created or self.throw(400, "E40002")
        return gd

    def create_user(self, name, contact, **kwargs):
        re.match("^[a-zA-Z0-9_]{2,32}$", name) or self.throw(400,
                                                    "E40017")
        meta              = kwargs.copy()
        meta["last_login_from"] = "0.0.0.0"
        meta["contact"]   = contact
        meta["name"]      = name
        user, created = User.get_or_create(name=name,
                                           defaults=meta)
        created or self.throw(400, "E40003")
        return user

    def write_error(self, status, exc_info=None,
                                        **kwargs):
        if status == 500:
            self._reason = "E50000"
        if status == 400 and not self._reason.startswith("E40"):
            self._reason = "E40000"
        try:
            self.finish({"status": status, "error": self._reason,
                     "message": exc_info[1].log_message})
        except AttributeError:
            traceback.print_exception(*exc_info)
            self.finish({"status": 500, "error": "E50000",
                     "message": "Internal Server Error"})


    def __init__(self, *args, **kwargs):
        super(BaseHttpService, self).__init__(*args, **kwargs)
        self.ioloop = tornado.ioloop.IOLoop.current()
        self.ctl = self.application.settings["ctl"]

    async def call_sync_async(self, func, *args):
        return await self.ioloop.run_in_executor(None,
                                        func, *args)

    def timestamp(self):
        return int(time.time())

    def tell(self, response):
        data = dict(status=0, message=None)
        data.update(response)
        self.write(data)

    def throw(self, status, error=None,
                                message=None):
        message = message or errors.get(error)
        raise HTTPError(status, reason=error,
                        log_message=message)


class DefaultHttpService(BaseHttpService):
    def prepare(self, *args, **kwargs):
        raise HTTPError(404)


class PlatformValidateHandler(BaseHttpService):
    def head_default(self, domain):
        u, _ = self.get_login_user_device(domain)
        self.set_header("X-ClientId", u.name)
    def head_novnc(self, _):
        u = self.get_login_user_admin()
        self.set_header("X-ClientId", u.name)
    def head(self, domain):
        func = getattr(self, f"head_{domain}",
                            self.head_default)
        func(domain)


class PlatformInfoHandler(BaseHttpService):
    @cachetools.func.ttl_cache(ttl=5*60)
    def get_top_info(self):
        data = {}
        info = self.ctl.info()
        data["expire"] = info["data"]["expire"]
        data["limit"] = info["data"]["limit"]
        return data
    @cachetools.func.ttl_cache(ttl=5)
    def get_info(self, *args):
        user = self.get_login_user()
        sel = Device.select().join(UserDevice).where(
                                UserDevice.user==user)
        total = sel.count()
        usable = sel.where( (Device.state==STATE_ONLINE)
                          & (Device.locked==False)).count()
        working = sel.where((Device.state==STATE_ONLINE)
                          & (Device.locked==True) ).count()
        offline = sel.where((Device.state==STATE_OFFLINE)
                                                  ).count()
        res = {}
        res["node"]     = platform.node()
        res["version"]  = __version__
        res["uptime"]   = int(psutil.Process().create_time())
        res["usable"]   = usable
        res["offline"]  = offline
        res["working"]  = working
        res["total"]    = total
        res.update(self.get_top_info())
        return dict(data=res)
    async def get(self, *args):
        res = await self.call_sync_async(self.get_info)
        self.tell(res)


class PlatformSpecificDeviceHandler(BaseHttpService):
    def to_dict(self, r):
        d = r.to_dict(exclude=[         Device.id,
                                        Device.lock,
                                        Device.frida,
                                        Device.auth])
        d["gateway_port"] = int(os.environ["API_PORT"])
        return d
    def get(self, domain):
        _, d = self.get_login_user_device(domain)
        self.tell({"data": self.to_dict(d)})
    def remove(self, domain):
        user = self.get_login_user_admin()
        _, d = self.get_login_user_device(domain, user=user)
        res = self.ctl.deleteNode(d.token_id)
        d.delete_instance(recursive=True)
        return res
    async def delete(self, domain):
        res = await self.call_sync_async(self.remove,
                                domain)
        self.tell(res)


class PlatformSpecificDeviceCommentHandler(BaseHttpService):
    def put(self, domain):
        user = self.get_login_user_admin()
        _, d = self.get_login_user_device(domain, user=user)
        comment = self.get_argument("comment")
        d.comment = comment
        d.save()
        self.tell(dict(status=0))


class PlatformDeviceStatsHandler(BaseHttpService):
    def to_dict(self, r):
        return r.to_dict(exclude=[DeviceStatus.device,
                                  DeviceStatus.id,])
    def get(self, domain):
        _, d = self.get_login_user_device(domain)
        limit = int(self.get_argument("limit", 60))
        items = d.status.select().order_by(DeviceStatus.timestamp.desc()
                                                        ).limit(limit)
        data = {}
        res = [self.to_dict(i) for i in items]
        data["total"]   = len(res)
        data["data"]    = res
        self.tell(data)


class PlatformDeviceAllocHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(exclude=[User.password,
                                      User.token])
    def get(self, domain):
        sort = getattr(User,
                       self.get_argument("sort", "id"),
                                                        User.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = int(self.get_argument("page", 0))
        size = int(self.get_argument("size", 20))
        _, device = self.get_login_user_device(domain)
        sel = User.select().join(UserDevice).where(
                        UserDevice.device==device)
        items = sel.order_by(sort
                                ).paginate(page, size)
        data = {}
        data["page"] = page
        data["size"] = size
        users = [self.to_dict(i) for i in items]
        data["total"] = sel.count()
        data["data"]  = users
        self.tell(data)
    def delete(self, domain):
        uid = self.get_argument("id")
        _ = self.get_login_user_admin()
        user = self.get_normal_user_by_id(uid)
        r = self.remove_device_from_user(domain, user)
        data = dict(status=int(not r))
        self.tell(data)
    def post(self, domain):
        uid = self.get_argument("id")
        _ = self.get_login_user_admin()
        user = self.get_normal_user_by_id(uid)
        self.alloc_device_to_user(domain, user)
        data = dict(status=0)
        self.tell(data)


class PlatformDeviceHandler(BaseHttpService):
    def get_super_key(self, domain):
        text = self.application.settings["sid"]
        key = sha256((text + domain).encode()).hexdigest()[::2]
        return key
    def to_dict(self, r):
        return r.to_dict(only=[         Device.domain,
                                        Device.token_id,
                                        Device.comment,
                                        Device.boot_time,
                                        Device.disk_total,
                                        Device.mem_total,
                                        Device.cpu_count,
                                        Device.batt_charging,
                                        Device.api_available,
                                        Device.locked,
                                        Device.controlling,
                                        Device.brand,
                                        Device.device,
                                        Device.model,
                                        Device.abi,
                                        Device.version,
                                        Device.sdk,
                                        Device.hardware,
                                        Device.board,
                                        Device.reg_time,
                                        Device.state,])
    def new(self):
        domain = "d" + r_string(15)
        user = self.get_login_user_admin()
        comment = self.get_argument("comment", None)
        auth, cert = generate_client_pem(domain)
        meta = self.ctl.createNode(comment=domain)
        token = meta["data"]["token"]
        cfg = dict()
        evt = "device/${device_id}/event"
        cmd = "device/${device_id}/command"
        usr = "${device_id}"
        server = self.application.settings["server"]
        cfg["event"] = f"mqtt://{usr}:{token}@{server}/{evt}?command={cmd}&will={evt}&qos=2&qsize=64&keepalive=30&encode=msgpack/zlib"
        cfg["ssl-web-credential"] = self.get_super_key(domain)
        cfg["cert"] = b64encode(cert).decode()
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
        res["auth"]              = auth
        device = Device.create(**res)
        self.alloc_device_to_user(domain, user)
        return dict(data=self.to_dict(device))
    async def post(self):
        res = await self.call_sync_async(self.new)
        self.tell(res)
    def get(self, *args):
        sort = getattr(Device,
                       self.get_argument("sort", "id"),
                                                        Device.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = int(self.get_argument("page", 0))
        size = int(self.get_argument("size", 20))
        user = self.get_login_user()
        sel = Device.select().join(UserDevice).where(
                                UserDevice.user==user)
        items = sel.order_by(sort
                                ).paginate(page, size)
        data = {}
        data["page"] = page
        data["size"] = size
        devices = [self.to_dict(i) for i in items]
        data["total"] = sel.count()
        data["data"] = devices
        self.tell(data)


class PlatformDeviceDistributeHandler(BaseHttpService):
    def get(self, *args):
        user = self.get_login_user()
        sel = Device.select(Device.ip_country).join(UserDevice).where(
                                    UserDevice.user==user)
        data = {}
        data["total"] = sel.count()
        item = [item.ip_country for item in sel if item.ip_country]
        info = [dict(name=n, value=v) for n, v in Counter(item).items()]
        data["data"] = info
        self.tell(data)


class PlatformDeviceDistributeCountryHandler(BaseHttpService):
    def get(self, country):
        user = self.get_login_user()
        sel = Device.select(Device.ip_region).join(UserDevice).where(
                                    (Device.ip_country==country) &
                                    (UserDevice.user==user))
        data = {}
        data["total"] = sel.count()
        data["country"] = country
        item = [item.ip_region for item in sel if item.ip_region]
        info = [dict(name=n, value=v) for n, v in Counter(item).items()]
        data["data"] = info
        self.tell(data)


class PlatformDeviceDistributeRegionHandler(BaseHttpService):
    def get(self, country, region):
        user = self.get_login_user()
        sel = Device.select(Device.ip_city).join(UserDevice).where(
                                    (Device.ip_country==country) &
                                    (Device.ip_region==region) &
                                    (UserDevice.user==user))
        data = {}
        data["total"] = sel.count()
        data["country"] = country
        data["region"] = region
        item = [item.ip_city for item in sel if item.ip_city]
        info = [dict(name=n, value=v) for n, v in Counter(item).items()]
        data["data"] = info
        self.tell(data)


class PlatformIndexHandler(BaseHttpService):
    def get(self, **kwargs):
        self.render("index.html",
                        **kwargs)


class PlatformUserLoginHandler(BaseHttpService):
    def to_dict(self, user):
        res = user.to_dict(exclude=[User.password])
        return dict(data=res)
    def get(self):
        u = self.get_login_user()
        self.tell(self.to_dict(u))
    def post(self):
        name = self.get_argument("name")
        passwd = self.get_argument("password")
        u = self.get_user_with_password(name, passwd)
        u.last_login_from = self.request.remote_ip
        u.login_time = time.time()
        u.save()
        self.set_secure_cookie("token", u.name)
        self.tell(self.to_dict(u))
    def delete(self):
        self.clear_cookie("token")
        self.tell({})


class PlatformUserHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(exclude=[User.password,
                                      User.token])
    def get(self):
        sort = getattr(User,
                       self.get_argument("sort", "id"),
                                                        User.id)
        sort = getattr(sort,
                       self.get_argument("order", "asc"),
                                            sort.asc)()
        page = int(self.get_argument("page", 0))
        size = int(self.get_argument("size", 20))
        u = self.get_login_user_admin()
        items = User.select().order_by(sort).paginate(
                                            page, size)
        data = {}
        data["page"] = page
        data["size"] = size
        users = [self.to_dict(i) for i in items]
        data["total"] = User.select().count()
        data["data"]  = users
        self.tell(data)
    def post(self):
        u = self.get_login_user_admin()
        name = self.get_argument("name")
        password = self.get_argument("password")
        contact = self.get_argument("contact", None)
        u = self.create_user(name, contact, password=password)
        self.tell(dict(data=self.to_dict(u)))


class PlatformSpecificUserHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(exclude=[User.password,
                                      User.token])
    def get(self, uid):
        u = self.get_user_admin_or_self(uid)
        self.tell(dict(data=self.to_dict(u)))
    def delete(self, uid):
        m = self.get_login_user()
        u = self.get_user_admin_or_self(uid)
        u.id == m.id and self.throw(400, "E40004")
        u.delete_instance(recursive=True)
        self.tell(dict(status=0))


class PlatformSpecificUserCredHandler(BaseHttpService):
    def to_dict(self, user):
        return user.to_dict(exclude=[User.password,
                                      User.token])
    def put(self, uid):
        u = self.get_user_admin_or_self(uid)
        password = self.get_argument("password", None)
        contact = self.get_argument("contact", None)
        u.contact = contact or u.contact
        u.password = password or u.password
        u.save()
        self.tell(dict(data=self.to_dict(u)))


class MqttClientAuthHandler(BaseHttpService):
    def prepare(self):
        return # No API Auth
    def post(self):
        su = self.application.settings["sid"]
        ss = self.application.settings["secret"]
        password = self.get_argument("password")
        username = self.get_argument("username")
        if username == su and password == ss: return # server
        device = self.get_device_by_token(password)
        device.dev_id = username
        device.save()


class MqttClientSuperUserAuthHandler(BaseHttpService):
    def prepare(self):
        return # No API Auth
    def post(self):
        return # NO ACL BUT SHOULD


class MqttClientAclAuthHandler(BaseHttpService):
    def prepare(self):
        return # No API Auth
    def post(self):
        return # NO ACL BUT SHOULD

# 全局任务存储
running_tasks = {}


def format_china_time(timestamp):
    """将时间戳转换为格式化的中国时间字符串"""
    # 将时间戳转换为UTC时间
    utc_time = datetime.datetime.fromtimestamp(timestamp, tz=timezone.utc)
    # 转换为中国时间（UTC+8）
    china_time = utc_time.astimezone(timezone(datetime.timedelta(hours=8)))
    # 格式化为字符串
    return china_time.strftime("%Y-%m-%d %H:%M:%S")

class PlatformDeviceBatchScriptHandler(BaseHttpService):
    def initialize(self, *args, **kwargs):
        super().initialize(*args, **kwargs)
        # 创建一个线程池执行器用于运行长时间任务
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    async def post(self, script_name):
        user = self.get_login_user_admin()
        
        # 从请求体获取JSON数据
        try:
            json_data = json.loads(self.request.body.decode())
            devices = json_data.get("devices", [])
            data = json_data.get("data", {})
        except json.JSONDecodeError:
            self.throw(400, "E40000", "Invalid JSON format in request body")
        
        if not devices:
            self.throw(400, "E40000", "No devices specified in request body")
        
        # 验证所有设备都存在且属于当前用户
        for domain in devices:
            if not isinstance(domain, str):
                self.throw(400, "E40000", "Device domains must be strings")
            self.get_login_user_device(domain)
        
        # 脚本路径
        script_path = f"/user/code/{script_name}.py"
        
        # 检查脚本是否存在
        if not os.path.exists(script_path):
            self.throw(404, "E40406", f"Script {script_name}.py does not exist")
        
        # 创建任务ID
        task_id = str(uuid.uuid4())

        # 记录任务开始状态
        running_tasks[task_id] = {
            "script_path": script_path,
            "status": "running",
            "devices": devices,
            "start_date": format_china_time(time.time()),
            "start_time": time.time(),
            "result": None
        }
        
        # 异步启动脚本执行
        asyncio.create_task(self._execute_script_async(task_id, script_path, devices, data))
        
        # 立即返回任务ID，不等待脚本执行完成
        response = {
            "status": 0,
            "message": f"Script {script_name} started successfully",
            "task_id": task_id,
            "devices": devices,
            "data": running_tasks
        }
        
        self.tell(response)
    
    async def _execute_script_async(self, task_id, script_path, devices, data):
        """在后台异步执行脚本"""
        try:
            # 使用线程池在后台执行脚本
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor, 
                self._run_subprocess, 
                script_path, 
                devices,
                data
            )
            
            # 更新任务完成状态
            running_tasks[task_id].update({
                "script_path": script_path,
                "status": "completed",
                "result": {
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                },
                "end_date": format_china_time(time.time()),
                "end_time": time.time()
            })
            
        except subprocess.TimeoutExpired:
            # 即使超时也记录状态
            running_tasks[task_id].update({
                "script_path": script_path,
                "status": "timeout",
                "result": {
                    "error": "Script execution timed out"
                },
                "end_date": format_china_time(time.time()),
                "end_time": time.time()
            })
        except Exception as e:
            # 记录执行错误
            running_tasks[task_id].update({
                "status": "error",
                "result": {
                    "error": str(e)
                },
                "end_date": format_china_time(time.time()),
                "end_time": time.time()
            })
    
    def _run_subprocess(self, script_path, devices, data):
        """在单独线程中运行子进程，无超时限制"""
        cmd = ["python3", script_path]

        # 通过环境变量传递数据
        env = os.environ.copy()
        env['SCRIPT_DATA'] = json.dumps(data)
        env['DEVICES'] = json.dumps(devices)
        
        # 执行脚本，无超时限制
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env
        )
        
        return result

# 添加一个获取任务状态的处理器
class PlatformDeviceBatchScriptStatusHandler(BaseHttpService):
    async def get(self):
        user = self.get_login_user_admin()
        
        self.tell({"status": 0, "data": running_tasks})
    
    async def delete(self):
        """清理已完成的任务"""
        user = self.get_login_user_admin()
        
        task_id = self.get_argument("task_id", None)
        
        if task_id is None:
            for task_id in list(running_tasks.keys()):
                if running_tasks[task_id]["status"] in ["completed", "error", "timeout"]:
                    del running_tasks[task_id]
            self.tell({
                "status": 0,
                "message": "All completed tasks cleaned up",
                "data": running_tasks
            })
            return
        
        if task_id in running_tasks:
            # 检查任务是否已完成
            if running_tasks[task_id]["status"] in ["completed", "error", "timeout"]:
                del running_tasks[task_id]
                self.tell({
                    "status": 0, 
                    "message": f"Task {task_id} cleaned up",
                    "data": running_tasks
                })
            else:
                self.throw(400, "E40000", "Cannot delete running task")
        else:
            self.throw(404, "E40402", f"Task {task_id} not found")

class Service(object):
    def __init__(self, path="/run/server.sock"):
        http = HttpServiceManager(path)
        http.add_handler("/", "server.service",
                        handler="PlatformIndexHandler")
        # MQTT AUTH
        http.add_handler("/mqtt/auth", "server.service",
                        handler="MqttClientAuthHandler")
        http.add_handler("/mqtt/superuser", "server.service",
                        handler="MqttClientSuperUserAuthHandler")
        http.add_handler("/mqtt/acl", "server.service",
                        handler="MqttClientAclAuthHandler")
        # HEAD
        http.add_handler("/validate/([0-9a-z]+)", "server.service",
                        handler="PlatformValidateHandler")
        # PUT
        http.add_handler("/api/v1/device/([a-z0-9]+)/comment", "server.service",
                        handler="PlatformSpecificDeviceCommentHandler")
        # GET
        http.add_handler("/api/v1/device/distribute/(.*?)/(.*?)", "server.service",
                        handler="PlatformDeviceDistributeRegionHandler")
        http.add_handler("/api/v1/device/distribute/(.*?)", "server.service",
                        handler="PlatformDeviceDistributeCountryHandler")
        http.add_handler("/api/v1/device/distribute", "server.service",
                        handler="PlatformDeviceDistributeHandler")
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
        # GET
        http.add_handler("/api/v1/info", "server.service",
                        handler="PlatformInfoHandler")
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
        # POST - 批量脚本执行
        http.add_handler("/api/v1/device/batch/([a-z0-9]+)/script", "server.service",
                handler="PlatformDeviceBatchScriptHandler")
        # GET - 批量脚本状态查询
        http.add_handler("/api/v1/device/batch/task", "server.service",
                handler="PlatformDeviceBatchScriptStatusHandler")
        # DELETE - 清理任务
        http.add_handler("/api/v1/device/batch/task/([a-z0-9]+)", "server.service",
                handler="PlatformDeviceBatchScriptStatusHandler")
        self.http = http
    def exited(self, bridge):
        os._exit(bridge.exitCode)
    def bridge(self):
        bridge = TopClient(self.cfg["sid"],
                           self.cfg["sid"], ckey=self.cfg["ckey"],
                           endpoint=self.cfg["endpoint"])
        bridge.setDoneCallback(self.exited)
        bridge.start()
    def initialize(self):
        certdir.mkdir(parents=True, exist_ok=True)
        Device.create_table()
        DeviceStatus.create_table()
        User.create_table()
        UserDevice.create_table()
        Config.create_table()
        # set all device to offline status
        query = Device.update(state=STATE_OFFLINE).where(
                            Device.state != STATE_PENDING)
        query.execute()
        self.prepare_instance()
    @ignore_exception(None)
    def read_exist_config(self):
        cfg = json.loads(open("/user/service.json", "r").read())
        self.cfg.update(cfg)
    def prepare_instance(self):
        self.read_exist_config()
        User.select().count() != 0 or self.prepare()
    def prepare(self):
        tc = TopCtl(self.cfg["endpoint"], self.cfg["ckey"],
                                        self.cfg["secret"])
        net = tc.createNetwork(self.cfg["sid"])
        nc = TopNetworkCtl(net["data"]["token"], self.cfg["endpoint"],
                                        self.cfg["ckey"])
        nw = nc.setupNetwork()
        # create node same as network id
        no = nc.createNode(token=net["data"]["token"],
                           comment="server")
        server = str(ip_network(nw["data"]["network"])[1])
        ip = nc.setNodeStaticIp(net["data"]["token"], server,
                                            "random")
        config = dict()
        config["sid"] = self.cfg["sid"]
        config["server"] = server
        self.cfg.update(config)
        # save first initialized configs
        open("/user/service.json", "w").write(
                            json.dumps(config))

        meta              = dict()
        meta["contact"]   = None
        meta["last_login_from"] = "0.0.0.0"
        meta["name"]      = "admin"
        meta["password"]  = "firerpa"
        meta["admin"]     = True
        User.create(**meta)
    def run(self):
        define("ckey", type=str)
        define("endpoint", type=str)
        define("secret", type=str)
        tornado.options.parse_command_line()

        self.cfg = dict()
        self.cfg["sid"] = uuid.uuid4().hex # default
        self.cfg["secret"] = options.secret
        self.cfg["endpoint"] = options.endpoint
        self.cfg["ckey"] = options.ckey
        self.cfg["server"] = None

        # initialize() will rewrite the default cfg configuration at the appropriate time
        self.initialize()

        kwargs = {}
        kwargs["cookie_secret"] = self.cfg["sid"]
        kwargs["ctl"] = TopNetworkCtl(self.cfg["sid"], options.endpoint,
                                                   options.ckey)
        kwargs["server"] = self.cfg["server"]
        kwargs["secret"] = self.cfg["secret"]
        kwargs["sid"] = self.cfg["sid"]
        self.bridge()
        event = EventConnectionService(self.cfg["sid"], self.cfg["secret"], db)
        threading.Thread(target=event.mq_start, daemon=True).start()
        logger.setLevel(logging.DEBUG)
        self.http.start_server(**kwargs)