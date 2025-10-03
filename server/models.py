# Copyright 2022 rev1si0n (lamda.devel@gmail.com). All rights reserved.
#
# Distributed under MIT license.
# See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
#encoding=utf-8
import time
from playhouse.shortcuts import model_to_dict
from peewee import (SqliteDatabase, Model, IntegerField, FloatField,
                    BigIntegerField, CharField, TextField, DoubleField,
                    BooleanField, ForeignKeyField, SmallIntegerField)

from .utils import r_string


STATE_PENDING  = -1
STATE_OFFLINE  =  0
STATE_ONLINE   =  1


class BaseDatabaseModel(Model):
    class Meta:
        database = SqliteDatabase("/user/database.db", pragmas={
                                            "foreign_keys": "1",
                                            "locking_mode": "NORMAL",
                                            "journal_mode": "wal",
                                            "synchronous": "NORMAL"})
        only_save_dirty = True
    def to_dict(self, **kwargs):
        ret = model_to_dict(self, **kwargs)
        return ret


class Config(BaseDatabaseModel):
    name                = CharField(unique=True, index=True)
    value               = CharField()


class User(BaseDatabaseModel):
    name                = CharField(unique=True, index=True)
    contact             = CharField(null=True, index=True)

    password            = CharField()
    token               = CharField(default=r_string)

    last_login_from     = CharField(null=True)

    reg_time            = BigIntegerField(default=time.time)
    login_time          = BigIntegerField(default=0)
    admin               = BooleanField(default=False)


class Device(BaseDatabaseModel):
    domain              = CharField(unique=True, index=True)
    dev_id              = CharField(null=True, index=True)
    token_id            = CharField(unique=True, index=True)

    comment             = CharField(null=True, max_length=4096)

    service_port        = IntegerField(default=65000)

    top_ip              = CharField(null=True)
    vpn_ip              = CharField(null=True)
    default_ip          = CharField(null=True)

    boot_time           = IntegerField(null=True, default=0)

    disk_total          = IntegerField(null=True, default=0)
    mem_total           = IntegerField(null=True, default=0)
    cpu_count           = IntegerField(null=True, default=0)

    batt_charging       = BooleanField(null=True, default=False)
    api_available       = BooleanField(null=True, default=False)
    locked              = BooleanField(null=True, default=False)
    frida               = CharField(null=True) # frida token
    lock                = CharField(null=True) # lamda token

    controlling         = BooleanField(null=True, default=False)
    controlling_cid     = CharField(null=True)

    public_ip           = CharField(null=True)
    ip_lat              = DoubleField(null=True, default=0.0)
    ip_lng              = DoubleField(null=True, default=0.0)
    ip_country          = CharField(null=True)
    ip_region           = CharField(null=True)
    ip_city             = CharField(null=True)

    cert                = CharField(null=True, max_length=8192)
    auth                = CharField(null=True)

    brand               = CharField(null=True)
    device              = CharField(null=True)
    model               = CharField(null=True)
    abi                 = CharField(null=True)
    version             = CharField(null=True)
    sdk                 = CharField(null=True)
    hardware            = CharField(null=True)
    board               = CharField(null=True)

    reg_time            = BigIntegerField(null=True, default=time.time)
    heartbeat_time      = BigIntegerField(null=True, default=0)
    state               = SmallIntegerField(null=True, default=STATE_PENDING)


class UserDevice(BaseDatabaseModel):
    device              = ForeignKeyField(Device,
                                          backref="users",
                                          on_delete="CASCADE")
    user                = ForeignKeyField(User,
                                          backref="devices",
                                          on_delete="CASCADE")


class DeviceStatus(BaseDatabaseModel):
    device              = ForeignKeyField(Device, backref="status")
    batt_temperature    = FloatField(default=0)
    batt_percent        = FloatField(default=0)

    cpu_percent         = IntegerField(default=0)
    cpu_freq_current    = FloatField(default=0)
    cpu_freq_max        = FloatField(default=0)
    cpu_freq_min        = FloatField(default=0)
    cpu_times_user      = FloatField(default=0)
    cpu_times_system    = FloatField(default=0)
    cpu_times_idle      = FloatField(default=0)

    disk_used           = IntegerField(default=0)
    disk_free           = IntegerField(default=0)
    disk_percent        = FloatField(default=0)

    disk_io_read_bytes  = IntegerField(default=0)
    disk_io_read_count  = IntegerField(default=0)
    disk_io_write_bytes = IntegerField(default=0)
    disk_io_write_count = IntegerField(default=0)
    disk_io_read_time   = IntegerField(default=0)
    disk_io_write_time  = IntegerField(default=0)
    disk_io_busy_time   = IntegerField(default=0)

    net_io_bytes_sent   = IntegerField(default=0)
    net_io_packets_sent = IntegerField(default=0)
    net_io_bytes_recv   = IntegerField(default=0)
    net_io_packets_recv = IntegerField(default=0)

    mem_available       = IntegerField(default=0)
    mem_percent         = FloatField(default=0)
    mem_used            = IntegerField(default=0)
    mem_free            = IntegerField(default=0)
    mem_active          = IntegerField(default=0)
    mem_inactive        = IntegerField(default=0)
    mem_buffers         = IntegerField(default=0)
    mem_cached          = IntegerField(default=0)
    mem_shared          = IntegerField(default=0)
    mem_slab            = IntegerField(default=0)

    process_count       = IntegerField(default=0)
    thread_count        = IntegerField(default=0)
    fd_count            = IntegerField(default=0)
    crash_count         = IntegerField(default=0)
    udpcon_count        = IntegerField(default=0)
    tcpcon_count        = IntegerField(default=0)

    wlan_linkspeed      = IntegerField(default=0)
    wlan_freq           = IntegerField(default=0)
    wlan_rssi           = IntegerField(default=0)
    timestamp           = BigIntegerField(default=time.time)