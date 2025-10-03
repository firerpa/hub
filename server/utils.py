# Copyright 2022 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import os
import uuid
import json
import random
import requests
import IP2Location
import threading

from hashlib import sha256
from OpenSSL import crypto

from python_hosts import Hosts, HostsEntry

from os.path import isfile

usrdir = os.path.expanduser("~")
current = os.path.dirname(__file__)

ip2location_lock = threading.Lock()
hosts_file_lock = threading.Lock()

geo = IP2Location.IP2Location()
geo.open(os.path.join(current, "IPDB.BIN"))


__all__ = ["generate_client_pem",
           "current", "ignore_exception",
           "r_string", "usrdir", "geo", "get_public_ip_info",
           "remove_host_entry", "add_host_entry",
           "save_cert", "remove_cert"]


def with_lock(lock):
    def wraps(func):
        def wrapper(*args, **kwargs):
            with lock:
                return func(*args, **kwargs)
        return wrapper
    return wraps


def ignore_exception(value):
    def wraps(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception:
                return value
        return wrapper
    return wraps


@with_lock(hosts_file_lock)
@ignore_exception(None)
def remove_host_entry(domain):
    hosts = Hosts()
    hosts.remove_all_matching(name=domain)
    hosts.write()


@with_lock(hosts_file_lock)
@ignore_exception(None)
def add_host_entry(ip, domain, comment=None):
    hosts = Hosts()
    new_entry = HostsEntry(entry_type="ipv4", address=ip,
                           names=[domain], comment=comment)
    hosts.add([new_entry], force=True)
    hosts.write()


@ignore_exception(False)
def save_cert(certdir, domain, text):
    certpath = certdir.joinpath(f"{domain}.pem")
    certpath.write_text(text)
    return True


@ignore_exception(False)
def remove_cert(certdir, domain):
    certpath = certdir.joinpath(f"{domain}.pem")
    certpath.unlink()
    return True


def r_string(n=32):
    return "".join(random.sample("abcdefhiklmnorsu"\
                                    "tuvwxz0123456789", n))


def create_root_keypair():
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    data = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    key = os.path.join(usrdir, "root.key")
    with open(key, "wb") as fd:
        fd.write(data)

    c = crypto.X509()
    c.get_subject().O = "LAMDA"
    c.gmtime_adj_notBefore(0)
    c.gmtime_adj_notAfter(315360000)
    c.set_issuer(c.get_subject())
    c.set_pubkey(k)
    c.sign(k, "sha256")
    data = crypto.dump_certificate(crypto.FILETYPE_PEM, c)
    crt = os.path.join(usrdir, "root.crt")
    with open(crt, "wb") as fd:
        fd.write(data)


def try_create_root_keypair():
    key = os.path.join(usrdir, "root.key")
    crt = os.path.join(usrdir, "root.crt")
    if not (isfile(key) and isfile(crt)):
        create_root_keypair()


def load_root_key(fpath):
    data = open(fpath, "rb").read()
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, data)
    return key


def load_root_cert(fpath):
    data = open(fpath, "rb").read()
    root = crypto.load_certificate(crypto.FILETYPE_PEM, data)
    return root


def generate_client_pem(CN):
    try_create_root_keypair()
    rk = load_root_key(os.path.join(usrdir, "root.key"))
    root = load_root_cert(os.path.join(usrdir, "root.crt"))

    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 2048)

    req = crypto.X509Req()
    req.set_version(0)
    req.get_subject().CN    = CN
    req.set_pubkey(pk)
    req.sign(pk, "sha256")

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_subject(req.get_subject())
    cert.set_serial_number(random.randint(1, 2**128))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_issuer(root.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(rk, "sha256")

    pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pk)
    cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    root = crypto.dump_certificate(crypto.FILETYPE_PEM, root)

    d = pk.to_cryptography_key().private_numbers().d
    data = d.to_bytes((d.bit_length() + 7)//8, "little")
    cred = sha256(data).hexdigest()[::3]

    buffer = []
    buffer.append(pkey.strip())
    buffer.append(cert.strip())
    buffer.append(root.strip())
    return cred, b"\n".join(buffer)


@with_lock(ip2location_lock)
@ignore_exception({})
def get_public_ip_info(ip):
    info = geo.get_all(ip)
    float(info.latitude)
    return info.__dict__