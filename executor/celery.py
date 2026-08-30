# Copyright 2025 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
from celery import Celery

app = Celery("executor")
app.config_from_object("executor.config.Celery")
app.autodiscover_tasks()