# Copyright 2022 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import os
import uuid

from OpenSSL import crypto
from base64 import b64encode
from ipaddress import ip_network
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .top import TopCtl, TopNetworkCtl
from .models import *
from .utils import *

init_engine = create_engine(f"postgresql+psycopg://postgres:{os.environ['POSTGRES_PASSWORD']}@postgres:5432/pigeon", pool_size=8, max_overflow=8, pool_recycle=300, pool_timeout=30, pool_pre_ping=True)
InitSession = sessionmaker(bind=init_engine, autocommit=False, autoflush=True, expire_on_commit=False)


class Initializer(object):
    def __init__(self, *args, **kwargs):
        self.session = InitSession()
    def prepare(self, sid, endpoint, ckey, secret):
        self.session.query(User).count() != 0 or self._prepare(sid,
                                        endpoint, ckey, secret)
    def initialize(self, sid, endpoint, ckey, secret):
        Base.metadata.create_all(bind=init_engine)
        certdir.mkdir(parents=True, exist_ok=True)
        self.prepare(sid, endpoint, ckey, secret)
        self.session.query(Device).filter(
                            Device.state != DeviceState.PENDING.value).update(
                                dict(state=DeviceState.OFFLINE.value),
                                     synchronize_session=False)
        self.session.commit()
        self.session.close()
    def _prepare_main(self, sid):
        private = crypto.PKey()
        private.generate_key(crypto.TYPE_RSA, 2048)
        private_key_der = crypto.dump_privatekey(crypto.FILETYPE_ASN1, private)
        public_key_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, private)
        skey = b64encode(private_key_der).decode()
        ckey = b64encode(public_key_der).decode()
        self.session.add(Config(name="sid", value=sid))
        self.session.add(Config(name="sapi_skey", value=skey))
        self.session.add(Config(name="sapi_ckey", value=ckey))
        self.session.commit()
        meta = dict()
        meta["contact"]             = None
        meta["last_login_ip"]       = "0.0.0.0"
        meta["name"]                = "admin"
        meta["password"]            = "pigeon"
        meta["is_admin"]            = True
        self.session.add(User(**meta))
        self.session.commit()
        self.session.flush()
    def _prepare_p2p(self, sid, endpoint, ckey, secret):
        if not (endpoint or "").strip() or not (
                            ckey or "").strip():
            return None
        tc = TopCtl(endpoint, ckey, secret)
        net = tc.createNetwork(sid)
        nc = TopNetworkCtl(net["data"]["token"],
                                endpoint, ckey)
        nw = nc.setupNetwork()
        # create node same as network id
        _ = nc.createNode(token=net["data"]["token"],
                           comment="server")
        server = str(ip_network(nw["data"]["network"])[1])
        _ = nc.setNodeStaticIp(net["data"]["token"], server,
                                            "random")
        # save config
        self.session.add(Config(name="top_server", value=server))
        self.session.add(Config(name="top_endpoint", value=endpoint))
        self.session.add(Config(name="top_client_key", value=ckey))
        self.session.add(Config(name="top_secret", value=secret))
        self.session.add(Config(name="top_available", value="true"))
        self.session.commit()
        self.session.flush()
    def _prepare(self, sid, endpoint, ckey, secret):
        self._prepare_main(sid)
        self._prepare_p2p(sid, endpoint,
                                    ckey, secret)


if __name__ == "__main__":
    Initializer().initialize(uuid.uuid4().hex[::2],
                    os.environ.get("TOP_ENDPOINT"),
                    os.environ.get("TOP_CLIENT_KEY"),
                    os.environ.get("TOP_SECRET"))