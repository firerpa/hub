#!/usr/bin/env python3
# Copyright 2025 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import os
import json
import time
import random
import tornado.web
import tornado.ioloop
import tornado.httpserver

import logging
import requests
import traceback
import asyncio

from collections import OrderedDict
from base64 import b64encode, b64decode
from zlib import decompress as unz, compress as z

from urllib3.util import SKIP_HEADER
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from tornado import httputil
from tornado.web import Application, _ArgDefaultMarker
from tornado.options import define, options
from tornado.web import HTTPError
from tornado.ioloop import IOLoop

logger = logging.getLogger("sapi")

"""
Secure API Communication Framework

SAPI is a secure API communication system based on Tornado and Crypto libraries,
using RSA asymmetric encryption to transmit AES symmetric keys for encrypted
communication between client and server. Includes client request class,
server handler class, and HTTP server manager.
"""

__all__ = ["logger", "SecureAPIClient", "SecureAPIClientError", "HttpServiceManager", "SecureAPIService"]


def encrypt_key_with_public_key(public_key, symmetric_key):
    public_key = b64decode(public_key)
    public_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(symmetric_key)
    return b64encode(encrypted_key)


def decrypt_key_with_private_key(private_key, encrypted_key_base64):
    private_key = b64decode(private_key)
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_key = b64decode(encrypted_key_base64)
    symmetric_key = cipher_rsa.decrypt(encrypted_key)
    return symmetric_key


def aes_encrypt(key, plaintext):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    z_text = z(plaintext, 4)
    ciphertext = cipher.encrypt(pad(z_text, AES.block_size))
    combined = iv + ciphertext
    return b64encode(combined)


def aes_decrypt(key, encrypted_data_base64):
    combined = b64decode(encrypted_data_base64)
    iv = combined[:AES.block_size]
    ciphertext = combined[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    zd = int.from_bytes(plaintext[:2], "big") in (0x7801, 0x789c,
                                                  0x78da, 0x785e)
    return unz(plaintext) if zd else plaintext


class SecureAPIClientError(Exception):
    """ SecureAPIClientError """


class SecureAPIClient(object):
    def __init__(self, url, ckey, retries=3, max_backoff=5,
                                         backoff_factor=1.0,
                        retry_status=[500, 502, 503, 504],
                        noraise=False):
        self.s = requests.Session()
        class MaxIntervalRetry(Retry):
            DEFAULT_BACKOFF_MAX = max_backoff
        retry = MaxIntervalRetry(total=retries,
                                 backoff_factor=backoff_factor,
                                 status_forcelist=retry_status)
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        self.s.headers["Accept"] = None
        self.s.headers["Accept-Encoding"] = SKIP_HEADER
        self.s.headers["User-Agent"] = SKIP_HEADER
        self.noraise = noraise
        self.ckey = ckey
        self.url = url
    def raise_exc(self, msg):
        raise SecureAPIClientError(msg)
    def raise_remote_exc(self, res):
        err = res["status"] != 0 and not self.noraise
        message = res.get("message") or res.get("error")
        err and self.raise_exc(message)
    def reraise_remote_exc(self, res):
        err = res["status"] != 0
        message = res.get("message") or res.get("error")
        err and self.raise_exc(message)
    def do_request(self, data=None):
        key = os.urandom(32)
        s = encrypt_key_with_public_key(self.ckey, key)
        data = aes_encrypt(key, json.dumps(data, separators=(",", ":")).encode())
        res = self.s.post(self.url, params=dict(s=s.decode()),
                                                verify=False,
                                                data=data)
        data = aes_decrypt(key, res.content)
        return json.loads(data)
    def request(self, name, args=None):
        data = dict()
        data["api"] = name
        data["args"] = args or {}
        res = self.do_request(data=data)
        self.raise_remote_exc(res)
        return res


class HttpServiceManager(object):
    def __init__(self, bind="0.0.0.0", port=9000,
                                      root=None):
        self.handlers = OrderedDict()
        cur_dir = root or os.path.dirname(__file__)
        self.static = os.path.join(cur_dir, "static")
        self.template = os.path.join(cur_dir, "html")
        self.bind = bind
        self.port = port

    def add_handler(self, route, handle, *args):
        self.handlers[route] = (route, handle, *args)

    def start_server(self, **settings):
        kwargs = {}
        kwargs["debug"] = False
        kwargs["template_path"] = self.template
        kwargs["compiled_template_cache"] = True
        kwargs["static_path"] = self.static
        kwargs.update(settings)
        app = Application(self.handlers.values(),
                                        **kwargs)
        server = tornado.httpserver.HTTPServer(app)
        server.bind(self.port, address=self.bind)
        server.start (0)
        loop = asyncio.get_event_loop()
        self.ioloop = IOLoop.current()
        self.ioloop.start()


class SecureAPIService(tornado.web.RequestHandler):
    def throw(self, status, error=None,
                                message=None):
        message = message or self.errors.get(error)
        raise HTTPError(status, reason=error,
                        log_message=message)

    def r_string(self, n):
        return "".join(random.sample("abcdefhiklmnors"\
                                     "tuvwxz0123456789", n))

    def timestamp(self):
        return int(time.time())

    def set_default_headers(self):
        self._headers.pop("Date", None)
        self._headers.pop("Content-Type", None)
        self._headers.pop("Server", None)

    def initialize(self, skey=None, errors=None,
                                        **configs):
        self.skey = skey
        self.api_ekey = None
        self.errors = errors or dict()
        self.kwargs = configs

    def prepare(self):
        s = self.get_query_argument("s")
        ekey = decrypt_key_with_private_key(self.skey, s)
        body = aes_decrypt(ekey, self.request.body)
        data = json.loads(body)
        self.api_args = data.get("args", {})
        self.api_name = data.get("api")
        self.api_ekey = ekey

    def write_error(self, status, exc_info=None,
                                        **kwargs):
        error = self._reason
        self._reason = httputil.responses.get(status, "Unknown")
        status = 0 if status in (0, 200) else status
        try:
            self.tell(None, status=status, error=error,
                      message=exc_info[1].log_message or self._reason)
        except AttributeError:
            traceback.print_exception(*exc_info)
            self.tell(None, status=500, error="Internal Server Error",
                      message="An unexpected error has occurred")

    def __init__(self, *args, **kwargs):
        super(SecureAPIService, self).__init__(*args, **kwargs)
        self.ioloop = tornado.ioloop.IOLoop.current()

    async def call_sync_async(self, func, *args):
        return await self.ioloop.run_in_executor(None,
                                        func, *args)

    def tell(self, data, **kwargs):
        message = dict(status=0, error=None,
                                message="OK")
        message.update(kwargs)
        message["data"] = data
        if self.api_ekey == None:
            return self.write(message)
        payload = aes_encrypt(self.api_ekey, json.dumps(message,
                              separators=(",", ":")).encode())
        self.write(payload)

    async def comm(self, *args):
        method = self.request.method.lower()
        call = getattr(self, f"http_{method}",
                                self.default)
        r = await self.call_sync_async(call,
                                    *args)
        self.tell(r)

    def http_post(self):
        return getattr(self, f"api_{self.api_name}",
                                self.api_default)()
    def get_api_argument(self, name, default=_ArgDefaultMarker()):
        result = self.api_args.get(name) or default
        if isinstance(result, _ArgDefaultMarker): self.throw(400,
                          message="Missing argument %s" % name)
        return result
    def get_api_config(self, name, default=_ArgDefaultMarker()):
        result = self.kwargs.get(name) or default
        if isinstance(result, _ArgDefaultMarker): self.throw(400,
                          message="Missing config %s" % name)
        return result
    def api_default(self, *args):
        self.throw(501)

    def http_get(self, *args):
        self.throw(501)
    def http_delete(self, *args):
        self.throw(501)
    def http_patch(self, *args):
        self.throw(501)
    def http_put(self, *args):
        self.throw(501)
    def http_head(self, *args):
        self.set_status(200)
    def default(self, *args):
        self.throw(404)

    async def get(self, *args):
        await self.comm(*args)
    async def delete(self, *args):
        await self.comm(*args)
    async def post(self, *args):
        await self.comm(*args)
    async def patch(self, *args):
        await self.comm(*args)
    async def head(self, *args):
        await self.comm(*args)
    async def put(self, *args):
        await self.comm(*args)
