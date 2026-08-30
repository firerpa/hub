# Copyright 2025 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import os
import time
import zlib
import uuid
import json
import redis
import logging
import threading
import zstandard as zstd
import paho.mqtt.client as mqtt

from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

from json import dumps as json_dump
from msgpack import loads as msgpack_load, dumps as msgpack_dump

from .queue import enqueue_event_and_get_first_if_idle, reordered_queue_add_event
from .handlers.event import handle
from .utils import *

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

db = redis.StrictRedis.from_url(f"redis://:{os.environ['REDIS_PASSWORD']}@redis-master/0")


class EventConnectionService(object):
    def __init__(self, username, passwd):
        client = mqtt.Client(client_id="event-loop",
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                                    protocol=mqtt.MQTTv5,
                                    transport="unix")
        self.client = client
        client.username_pw_set(username, passwd)
        client.on_connect = self.mq_on_connect
        client.on_disconnect = self.mq_on_disconnect
        client.on_message = self.mq_on_message
        client.max_queued_messages_set(65535)
        self.encode = "msgpack/zstd"
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
        message["received"] = time.time()
        message["message_id"] = up["message_id"]
        message["session_id"] = up.get("session_id", "")
        message["sequence"] = int(up.get("sequence"))
        self.get_func(message)(message)
    def mq_start(self):
        self.client.connect("/run/mosquitto/server.sock",
                                    1883, keepalive=60)
        self.fwd = threading.Thread(target=self.forward,
                                            daemon=True)
        self.fwd.start()
        self.fwe = threading.Thread(target=self.eventer,
                                            daemon=True)
        self.fwe.start()
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
    def mq_enc_msgpack_zstd(self, data):
        c = zstd.ZstdCompressor(level=3)
        return "msgpack/zstd", c.compress(
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
    def mq_dec_msgpack_zstd(self, data):
        d = zstd.ZstdDecompressor()
        return msgpack_load(d.decompress(data))
    def dispatch(self, device_id, event, data):
        for ev in reordered_queue_add_event(device_id, event, data):
            first = enqueue_event_and_get_first_if_idle( device_id,
                                                                ev)
            if first:
                handle.apply_async((device_id, first),
                                                ignore_result=True,
                                                    countdown=0)
    def handle_DEFAULT(self, message):
        logger.error(message)
    def handle_BYE(self, data):
        self.dispatch(data["device_id"], "BYE", data)
    def handle_HELO(self, data):
        self.dispatch(data["device_id"], "HELO", data)
        # get base information when client connected
        self.mq_send_command(data["device_id"], "cloud/helo", None)
    def handle_CLOUD_HELO(self, data):
        self.dispatch(data["device_id"], "CLOUD_HELO", data)
    def handle_CONTROL_ENTER(self, data):
        self.dispatch(data["device_id"], "CONTROL_ENTER", data)
    def handle_CONTROL_LEAVE(self, data):
        self.dispatch(data["device_id"], "CONTROL_LEAVE", data)
    def handle_DEVICE_STATUS(self, data):
        self.dispatch(data["device_id"], "DEVICE_STATUS", data)
    def handle_LOCK(self, data):
        self.dispatch(data["device_id"], "LOCK", data)
    def handle_UNLOCK(self, data):
        self.dispatch(data["device_id"], "UNLOCK", data)
    def handle_TASK_STATUS(self, data):
        self.dispatch(data["device_id"], "TASK_STATUS", data)
    def handle_TASK_LOAD(self, data):
        self.dispatch(data["device_id"], "TASK_LOAD", data)
    def handle_TASK_LIST(self, data):
        self.dispatch(data["device_id"], "TASK_LIST", data)
    def handle_TASK_EXECUTE(self, data):
        self.dispatch(data["device_id"], "TASK_EXECUTE", data)
    def handle_TASK_PURGE(self, data):
        self.dispatch(data["device_id"], "TASK_PURGE", data)
    def handle_TASK_REVOKE(self, data):
        self.dispatch(data["device_id"], "TASK_REVOKE", data)
    def handle_TASK_MESSAGE(self, data):
        self.dispatch(data["device_id"], "TASK_MESSAGE", data)
    def handle_TASK_SUCCEEDED(self, data):
        self.dispatch(data["device_id"], "TASK_SUCCEEDED", data)
    def handle_TASK_STARTED(self, data):
        self.dispatch(data["device_id"], "TASK_STARTED", data)
    def handle_TASK_RECEIVED(self, data):
        self.dispatch(data["device_id"], "TASK_RECEIVED", data)
    def handle_TASK_RETRIED(self, data):
        self.dispatch(data["device_id"], "TASK_RETRIED", data)
    def handle_TASK_REVOKED(self, data):
        self.dispatch(data["device_id"], "TASK_REVOKED", data)
    def handle_TASK_FAILED(self, data):
        self.dispatch(data["device_id"], "TASK_FAILED", data)
    def handle_PING(self, data):
        self.dispatch(data["device_id"], "PING", data)
    def mq_send_event(self, topic, payload):
        self.client.publish(topic, payload,
                                      qos=0)
    def mq_send_command(self, device_id, command, payload,
                                    correlation_id=None):
        properties = dict()
        topic = f"device/{device_id}/command"
        data = dict()
        data["type"] = "command"
        data["device_id"] = device_id
        data["command"] = command
        data["correlation_id"] = correlation_id or str(uuid.uuid4())
        data["timestamp"] = int(time.time()*1000)
        data["data"] = payload
        properties["device_id"] = device_id
        properties["message_id"] = str(uuid.uuid4())
        properties["timestamp"] = str(int(time.time()*1000))
        properties["type"] = "command"
        encode, payload = self.mq_encode(data)
        properties["encode"] = encode
        pub_properties = Properties(PacketTypes.PUBLISH)
        pub_properties.UserProperty = sorted(properties.items())
        self.client.publish(topic, payload,
                            properties=pub_properties,
                                      qos=2)
    def forward(self):
        while True:
            _, data = db.brpop("mqtt/command")
            message = msgpack_load(data)
            correlation_id = message["correlation_id"]
            self.mq_send_command(message["id"],
                                 message["command"],
                                 message["data"],
                                 correlation_id=correlation_id)
    def eventer(self):
        while True:
            _, data = db.brpop("mqtt/event")
            message = json.loads(data)
            self.mq_send_event(message["topic"],
                               message["data"])