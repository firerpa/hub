# Copyright 2025 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import time
import zlib
import uuid
import json
import logging
import cachetools.func
import paho.mqtt.client as mqtt

from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

from pathlib import Path
from json import dumps as json_dump
from msgpack import loads as msgpack_load, dumps as msgpack_dump

from server.models import DeviceStatus, Device, STATE_OFFLINE, STATE_ONLINE, STATE_PENDING
from server.utils import *


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
certdir = Path("/user/certificates")


class EventConnectionService(object):
    def __init__(self, username, passwd, db):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                    client_id="main",
                                    protocol=mqtt.MQTTv5)
        self.client = client
        client.username_pw_set(username, passwd)
        client.on_connect = self.mq_on_connect
        client.on_disconnect = self.mq_on_disconnect
        client.on_message = self.mq_on_message
        self.encode = "msgpack/zlib"
        self.db = db
    def mq_on_connect(self, client, userdata, flags,
                                reason, properties):
        if reason != 0: return None
        self.client.subscribe("device/+/event",
                                        qos=2)
    def mq_on_disconnect(self, *args):
        logger.warning(f"EVENT-mq disconnected")
    def get_func(self, message):
        callback = message["type"]
        name = f"handle_{callback.replace('/', '_').upper()}"
        return getattr(self, name, self.handle_DEFAULT)
    def mq_on_message(self, client, userdata, msg):
        up = dict(msg.properties.UserProperty)
        message = self.mq_decode(msg.payload, encoding=up.get("encode"))
        d = Device.get_or_none(Device.dev_id==message["device_id"])
        self.get_func(message)(d, message)
    def mq_start(self):
        self.client.connect("127.0.0.1", 1883, 30)
        self.client.loop_forever(
                  retry_first_connection=True)
    def mq_encode(self, data):
        method = self.encode.replace("/", "_")
        func = getattr(self, f"mq_enc_{method}",
                             self.mq_enc_none)
        return func (data)
    def mq_enc_none(self, data):
        return "json", json_dump(data)
    def mq_enc_json(self, data):
        return self.mq_enc_none(data)
    def mq_enc_json_zlib(self, data):
        return "json/zlib", zlib.compress(
                            json_dump(data))
    def mq_enc_msgpack(self, data):
        return "msgpack", msgpack_dump(
                                        data)
    def mq_enc_msgpack_zlib(self, data):
        return "msgpack/zlib", zlib.compress(
                            msgpack_dump(data))
    def mq_decode(self, data, encoding=None):
        method = (encoding or self.encode).replace("/", "_")
        func = getattr(self, f"mq_dec_{method}",
                             self.mq_dec_none)
        return func (data)
    def mq_dec_none(self, data):
        return json.loads(data)
    def mq_dec_json(self, data):
        return self.mq_dec_none(data)
    def mq_dec_json_zlib(self, data):
        return json.loads(zlib.decompress(data))
    def mq_dec_msgpack(self, data):
        return msgpack_load(
                                        data)
    def mq_dec_msgpack_zlib(self, data):
        return msgpack_load(zlib.decompress(data))
    def handle_DEFAULT(self, d, message):
        logger.error(message)
    @cachetools.func.ttl_cache(ttl=60)
    def expire(self):
        deadline = (time.time() - 3.0*60)
        query = Device.update(state=STATE_OFFLINE).where((Device.heartbeat_time < deadline)
                                                       & (Device.state != STATE_PENDING))
        query.execute()
    def set_redis_map(self, d, host, port,
                                    ttl=10*60):
        rule = f"{host}:{port},{d.auth}"
        self.db.setex(f"gw:{d.domain}", int(ttl),
                                    rule)
    def update_public_ip_info(self, d, ip):
        info = get_public_ip_info(ip)
        d.public_ip = ip
        d.ip_lat    = info.get("latitude", 0)
        d.ip_lng    = info.get("longitude", 0)
        d.ip_country= info.get("country_long")
        d.ip_region = info.get("region")
        d.ip_city   = info.get("city")
    def handle_BYE(self, d, data):
        d.controlling_cid = None
        d.controlling = False
        d.state     = STATE_OFFLINE
        d.frida     = None
        d.lock      = None
        d.batt_charging = False
        d.api_available = False
        d.locked    = False
        self.db.delete(f"gw:{d.domain}")
        remove_host_entry(d.domain)
        remove_cert(certdir, d.domain)
        d.save()
    def handle_HELO(self, d, data):
        info = data["data"]
        d.dev_id        = data["device_id"]
        d.board         = info["board"]
        d.hardware      = info["hardware"]
        d.brand         = info["brand"]
        d.device        = info["device"]
        d.model         = info["model"]
        d.abi           = info["abi"]
        d.sdk           = info["sdk"]
        d.boot_time     = info["uptime"]
        d.version       = info["version"]
        d.state         = STATE_ONLINE
        d.heartbeat_time = time.time()
        d.save()
        # get base information when client connected
        self.mq_send_cmd(d.dev_id, "cloud/helo", None)
        self.mq_send_cmd(d.dev_id, "task/list", None)
    def handle_CLOUD_HELO(self, d, data):
        info = data["data"]
        d.top_ip        = info["top_ip"]
        d.vpn_ip        = info["vpn_ip"]
        d.default_ip    = info["default_ip"]
        d.service_port  = info["port"]
        self.update_public_ip_info(d, info.get("public_ip"))
        d.locked        = info["locked"]
        d.api_available = info["api_available"]
        d.frida         = info["frida"]
        d.lock          = info["lock"]
        d.controlling   = bool(info["controlling"])
        d.controlling_cid = info["controlling"]
        self.set_redis_map(d, info["top_ip"], info["port"],
                               ttl=2.5*60)
        add_host_entry(info["top_ip"], d.domain,
                       comment="firerpa")
        save_cert(certdir, d.domain,
                        d.cert)
        d.save()
    def handle_CONTROL_ENTER(self, d, data):
        info = data["data"]
        d.controlling = True
        d.controlling_cid = info["client"]
        d.save()
    def handle_CONTROL_LEAVE(self, d, data):
        d.controlling = False
        d.controlling_cid = None
        d.save()
    def handle_DEVICE_STATUS(self, d, data):
        info = data["data"]
        d.heartbeat_time = time.time()
        d.top_ip        = info["top_ip"]
        d.vpn_ip        = info["vpn_ip"]
        d.default_ip    = info["default_ip"]
        self.update_public_ip_info(d, info.get("public_ip"))
        d.service_port  = info["service_port"]
        d.mem_total     = info["mem_total"]
        d.disk_total    = info["disk_total"]
        d.cpu_count     = info["cpu_count"]
        d.batt_charging = info["batt_charging"]
        d.api_available = info["api_available"]
        d.state         = STATE_ONLINE
        d.locked        = info["locked"]
        d.save()
        host = info["top_ip"]
        port = info["service_port"]
        add_host_entry(info["top_ip"], d.domain, comment="firerpa")
        self.set_redis_map(d, host, port)
        r = DeviceStatus.create(device=d, **info)
        r.save()
        self.expire()
    def handle_LOCK(self, d, data):
        info = data["data"]
        d.frida         = info["frida"]
        d.lock          = info["lock"]
        d.locked        = True
        d.save()
    def handle_UNLOCK(self, d, data):
        d.lock          = None
        d.locked        = False
        d.save()
    def handle_PING(self, d, data):
        return self.handle_DEFAULT(d, data)
    def mq_send_cmd(self, device_id, command, payload):
        properties = dict()
        topic = f"device/{device_id}/command"
        data = dict()
        data["type"] = "command"
        data["device_id"] = device_id
        data["command"] = command
        data["correlation_id"] = str(uuid.uuid4())
        data["timestamp"] = int(time.time()*1000)
        data["data"] = payload
        properties["device"] = device_id
        properties["timestamp"] = str(int(time.time()*1000))
        properties["type"] = "command"
        encode, payload = self.mq_encode(data)
        properties["encode"] = encode
        pub_properties = Properties(PacketTypes.PUBLISH)
        pub_properties.UserProperty = sorted(properties.items())
        self.client.publish(topic, payload,
                            properties=pub_properties,
                                      qos=2)