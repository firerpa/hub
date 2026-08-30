#!/usr/bin/env python3
import os

from .models import *
from driver import TopClient
from contextlib import suppress

sid = Config.get("sid")
ckey = Config.get("top_client_key")
endpoint = Config.get("top_endpoint")

node = TopClient(sid, sid, ckey=ckey,
                             endpoint=endpoint)
with suppress(Exception): node.run()
os._exit (10)