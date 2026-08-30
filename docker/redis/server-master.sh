#!/bin/sh
cat <<EOL >/etc/redis.conf
bind 0.0.0.0

port 6379

pidfile /run/redis.pid
protected-mode yes
timeout 7200
tcp-keepalive 300
daemonize no
supervised no

replica-read-only yes
requirepass ${REDIS_PASSWORD:?REDIS_PASSWORD variable is not set}

loglevel notice
logfile ""
databases 16
always-show-logo no

save ""
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec

maxclients 65535
tcp-backlog 4096

dir /data
EOL

exec redis-server /etc/redis.conf