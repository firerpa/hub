# Copyright 2025 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
import os
from .event import EventConnectionService

EventConnectionService("local", os.environ.get("RUNTIMEPASSWD", "lamda")).mq_start()
exit (0)