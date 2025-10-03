# Copyright 2023 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
import os
import json
import requests

from base64 import b64encode, b64decode

from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


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
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    combined = iv + ciphertext
    return b64encode(combined)


def aes_decrypt(key, encrypted_data_base64):
    combined = b64decode(encrypted_data_base64)
    iv = combined[:AES.block_size]
    ciphertext = combined[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


class TopNetworkError(Exception):
    """ TopNetworkError """


class BaseTOPAPIClient(object):
    def __init__(self, url, ckey=None):
        self.s = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5)
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        self.noraise = False
        self.ckey = ckey
        self.url = url
    def raise_exc(self, msg):
        raise TopNetworkError(msg)
    def raise_remote_exc(self, res):
        err = res["status"] != 0 and not self.noraise
        message = res.get("message") or res.get("error")
        err and self.raise_exc(message)
        return True
    def do_request(self, data=None):
        key = os.urandom(32)
        s = encrypt_key_with_public_key(self.ckey, key)
        data = aes_encrypt(key, json.dumps(data).encode())
        res = self.s.post(self.url, params=dict(s=s.decode()),
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


class TopNetworkCtl(BaseTOPAPIClient):
    def __init__(self, network, url, ckey):
        super().__init__(url, ckey)
        self.network = network
    def listNode(self, page, size=10):
        """
        列出网络上的所有设备
        """
        data = self.request("listNode", dict(page=page, size=size,
                                      network=self.network))
        return data
    def setNodeConfig(self, nid, name, value):
        """
        设置节点配置
        """
        data = self.request("setNodeConfig", dict(name=name, value=value,
                                      node=nid, network=self.network))
        return data
    def putNodeConfig(self, nid, **config):
        """
        设置节点配置（批量）
        """
        data = self.request("putNodeConfig", dict(configs=config,
                                      node=nid, network=self.network))
        return data
    def delNodeConfig(self, nid, name):
        """
        删除节点配置
        """
        data = self.request("delNodeConfig", dict(name=name,
                                      node=nid, network=self.network))
    def listNodeConfig(self, nid):
        """
        列出所有节点配置
        """
        data = self.request("listNodeConfig", dict(node=nid,
                                        network=self.network))
        return data
    def getNodeInfo(self, nid):
        """
        获取设备配置信息
        """
        data = self.request("getNodeInfo", dict(node=nid,
                                        network=self.network))
        return data
    def deleteNode(self, nid):
        """
        从网络中删除一个设备
        """
        data = self.request("deleteNode", dict(node=nid,
                                        network=self.network))
        return data
    def createNode(self, token=None, comment=None):
        """
        新增一个设备
        """
        data = self.request("createNode", dict(comment=comment,
                                        token=token,
                                        network=self.network))
        return data
    def setNodeStaticIp(self, nid, v4, v6=None):
        """
        为设备设置静态地址
        """
        data = self.request("setNodeStaticIp", dict(v4=v4, v6=v6,
                                        node=nid, network=self.network))
        return data
    def info(self):
        """
        获取网络信息
        """
        data = self.request("getNetworkInfo", dict(network=self.network))
        return data
    def setNodeComment(self, nid, comment):
        """
        设置节点备注信息
        """
        data = self.request("getNetworkInfo", dict(node=nid, comment=comment,
                                                network=self.network))
        return data
    def setupNetwork(self, v4=None, v6=None):
        """
        设置网络的网段信息
        """
        data = self.request("setupNetwork", dict(v4=v4, v6=v6,
                                                network=self.network))
        return data


class TopCtl(BaseTOPAPIClient):
    def __init__(self, url, ckey, secret):
        super().__init__(url, ckey)
        self.secret = secret
    def createNetwork(self, token=None):
        data = self.request("createNetwork", dict(secret=self.secret,
                                                token=token))
        return data
    def disableNetwork(self, network):
        data = self.request("disableNetwork", dict(network=network,
                                                secret=self.secret))
        return data
    def enableNetwork(self, network):
        data = self.request("enableNetwork", dict(network=network,
                                                secret=self.secret))
        return data
    def listNetwork(self, page, size=10):
        data = self.request("listNetwork", dict(page=page, size=size,
                                                secret=self.secret))
        return data