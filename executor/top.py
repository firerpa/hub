# Copyright 2023 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
from .sapi import SecureAPIClient


class TopNetworkCtl(SecureAPIClient):
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


class TopCtl(SecureAPIClient):
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