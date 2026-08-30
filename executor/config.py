# Copyright 2025 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
import os
import redis

from datetime import timedelta
from celery.schedules import crontab

__all__ = ["aiodb", "db", "lockers", "Celery"]

redis_url = f"redis://:{os.environ['REDIS_PASSWORD']}@redis-master/0"
aiodb = redis.asyncio.Redis(connection_pool=redis.asyncio.ConnectionPool.from_url(redis_url,
                                                    max_connections=256,
                                                    health_check_interval=30))
db = redis.Redis(connection_pool=redis.ConnectionPool.from_url(redis_url,
                                                max_connections=256,
                                                health_check_interval=30))

lockers = [
     redis.StrictRedis.from_url(f"redis://:{os.environ['REDIS_PASSWORD']}@redis-lock01/0"),
     redis.StrictRedis.from_url(f"redis://:{os.environ['REDIS_PASSWORD']}@redis-lock02/0"),
     redis.StrictRedis.from_url(f"redis://:{os.environ['REDIS_PASSWORD']}@redis-lock03/0")
]


class Celery:
    include = [
        "executor.handlers.event",
    ]

    beat_schedule = {
"expire": {
    "task": "executor.handlers.event.expire",
    "schedule": crontab(minute="*/2"),
},
"sync": {
    "task": "executor.handlers.event.sync",
    "schedule": timedelta(seconds=60),
},
    }

    broker_connection_retry_on_startup = True
    worker_log_format = "[%(asctime)s: %(levelname)s/%(process)d] %(message)s"

    worker_lost_wait = 120

    worker_prefetch_multiplier = 1
    worker_disable_rate_limits = True
    task_ignore_result = False

    worker_concurrency = 128

    broker_url = f"amqp://rabbit:{os.environ['RABBITMQ_PASSWORD']}@rabbitmq:5672/"
    result_backend = f"redis://:{os.environ['REDIS_PASSWORD']}@redis-master/2"

    task_serializer = "msgpack"
    result_serializer = "msgpack"
    accept_content = ["msgpack"]
    timezone = "Asia/Shanghai"
    enable_utc = True