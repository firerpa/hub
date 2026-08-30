# Copyright 2025 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
import os
import json
import random
import socket

import pem as Pem
import tornado.ioloop
import tornado.web

from base64 import b64encode
from sqlalchemy import select
from tornado.web import HTTPError

from executor.sapi import SecureAPIService
from executor.handlers.event import set_gateway, host_from_mode
from executor.models import Config, Device, DeviceMode, session_scope
from executor.config import db


def get_occupied_forward_ports():
    with session_scope() as session:
        return set(session.scalars(select(Device.service_port).where(
                                                    Device.mode == DeviceMode.FORWARD.value,
                                                    Device.is_deleted == False)).all())


def get_free_forward_port(start, end):
    occupied_ports = get_occupied_forward_ports()
    for i in range(128):
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


def raise_if(condition, code, message):
    if condition: raise HTTPError(code,
                                                    log_message=message)


def get_device_by_domain(domain):
    with session_scope() as session:
        device = session.query(Device).filter(Device.domain == domain,
                                              Device.is_deleted == False).first()
        raise_if(not device, 404, f"Domain {domain} does not exist")
        return device


def get_device_by_domain_check_update(domain, dev_id):
    with session_scope() as session:
        alt = session.query(Device).filter(Device.dev_id == dev_id,
                                                  Device.domain != domain,
                                                  Device.is_deleted == False).first()
        alt_domain = alt.domain if alt else ""
        raise_if(alt, 409, f"Device {dev_id} already exists with a different domain {alt_domain}")
        device = session.query(Device).filter(Device.domain == domain,
                                              Device.is_deleted == False).first()
        raise_if(not device, 404, f"Domain {domain} does not exist")
        raise_if(device.dev_id is not None and device.dev_id != dev_id, 404, f"Device {dev_id} does not belong to the domain {device.domain}")
        if device.dev_id is None: device.dev_id = dev_id
        return device


class MqttClientAuthHandler(tornado.web.RequestHandler):
    def validate_local(self, username, password):
        raise_if(password != os.environ["RUNTIMEPASSWD"], 403, "Invalid Mqtt local")
    def validate_device(self, username, password):
        domain, token = password.split(".", 1)
        device = get_device_by_domain(domain)
        raise_if(device.token_id != token, 403, "Invalid Mqtt client")
        with session_scope() as session:
            session.query(Device).filter(Device.id == device.id).update(
                                                    dict(dev_id=username),
                                                    synchronize_session=False)
    def post(self):
        username = self.get_argument("username")
        password = self.get_argument("password")
        getattr(self, f"validate_{username}", self.validate_device)(
                                                   username, password)


class MqttClientSuperUserAuthHandler(tornado.web.RequestHandler):
    def validate_local(self):
        return True
    def validate_device(self):
        raise_if(True, 403, "Not superuser")
    def post(self):
        username = self.get_argument("username")
        getattr(self, f"validate_{username}",
                                                    self.validate_device)()
        self.set_status(200)


class MqttClientAclAuthHandler(tornado.web.RequestHandler):
    def post(self):
        username = self.get_argument("username")
        topic = self.get_argument("topic")
        raise_if(topic not in (f"device/{username}/command",
                               f"device/{username}/event"), 403, "Not authorized")
        self.set_status(200)


class FrpLoginAuthHandler(tornado.web.RequestHandler):
    def post(self):
        body = json.loads(self.request.body)
        password = body["content"]["metas"]["data"]
        user = body["content"]["user"]

        domain, token = password.split(".", 1)

        device = get_device_by_domain(domain)

        raise_if(device.token_id != token, 403, "Invalid Frp client")
        raise_if(device.dev_id and device.dev_id != user, 403, "Client exist")
        with session_scope() as session:
            session.query(Device).filter(Device.id == device.id).update(
                                                    dict(dev_id=user),
                                                    synchronize_session=False)
        self.write(dict(reject=False, unchange=True))


class FrpNewProxyHandler(tornado.web.RequestHandler):
    def post(self):
        body = json.loads(self.request.body)
        password = body["content"]["user"]["metas"]["data"]
        user = body["content"]["user"]["user"]
        content = body["content"]

        domain, token = password.split(".", 1)

        device = get_device_by_domain(domain)
        raise_if(device.token_id != token, 403, "Invalid Frp client")

        port = get_free_forward_port(20000, 60000)
        raise_if(not port, 403, "No Free port")
        with session_scope() as session:
            session.query(Device).filter(Device.id == device.id).update(
                                                    dict(service_port=port, dev_id=user),
                                                    synchronize_session=False)
        content["remote_port"] = port
        host = host_from_mode(device)
        set_gateway(device, host, port)
        self.write(dict(unchange=False, content=content))


class DeviceConfigPropertiesService(SecureAPIService):
    def api_getConfigProperties(self, domain):
        dev_id = self.get_api_argument("device_id")
        device = get_device_by_domain_check_update(domain, dev_id)

        endpoint = getattr(self, f"get_ip_{device.mode}")()

        key, crt, ca = Pem.parse(device.cert)
        key = b64encode(key.as_bytes()).decode()
        crt = b64encode(crt.as_bytes()).decode()
        ca  = b64encode(ca. as_bytes()).decode()

        config = {}
        extras = getattr(self, f"get_properties_{device.mode}")(device)
        config.update(extras)
        config["task.heartbeat"] = "10"
        config["task.concurrent"] = "true"
        config["event"] = f"mqtts://${{device_id}}:{device.domain}.{device.token_id}@{endpoint}/device/${{device_id}}/event?command=device/${{device_id}}/command&will=device/${{device_id}}/event&ca={ca}&key={key}&cert={crt}&qos=2&qsize=8192&keepalive=180&max_inflight_messages=20&session_expiry_interval=600&clean_start=false&encode=msgpack/zstd"
        config["cert"] = b64encode(device.cert.encode()).decode()
        config["port"] = str(random.randint(20000, 60000))
        return dict(properties=config)
    def get_ip_direct(self):
        return os.environ["LOCAL_LAN_IP"]
    def get_ip_forward(self):
        return os.environ["PUBLIC_IP"]
    def get_properties_direct(self, device):
        return dict()
    def get_properties_forward(self, device):
        config = dict()
        config["fwd.enable"] = "true"
        config["fwd.metadata"] = f"{device.domain}.{device.token_id}"
        config["fwd.host"] = os.environ["PUBLIC_IP"]
        config["fwd.port"] = os.environ["FWD_PORT"]
        return config


if __name__ == "__main__":
    sid = Config.get("sid")
    sapi_skey = Config.get("sapi_skey")
    handlers = list()
    handlers.append((r"/mqtt/auth", MqttClientAuthHandler))
    handlers.append((r"/mqtt/superuser", MqttClientSuperUserAuthHandler))
    handlers.append((r"/mqtt/acl", MqttClientAclAuthHandler))
    handlers.append((r"/frp/user", FrpLoginAuthHandler))
    handlers.append((r"/frp/port", FrpNewProxyHandler))
    handlers.append((r"/properties/(.*)", DeviceConfigPropertiesService,
                                            dict(skey=sapi_skey)))
    app = tornado.web.Application(handlers, sid=sid)

    app.listen(8123, address="127.0.0.1")
    tornado.ioloop.IOLoop.current().start()