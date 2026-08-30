#!/bin/sh
cat <<EOL >/etc/frps.toml
bindAddr = "0.0.0.0"

bindPort = ${FWD_PORT:-7000}
quicBindPort = ${FWD_PORT:-7000}

proxyBindAddr = "127.0.0.1"

transport.maxPoolCount = 16

transport.tls.force = true

log.level = "info"
log.disablePrintColor = true

auth.method = "token"
auth.token = ""

allowPorts = [ { start = 20000, end = 60000 } ]

[[httpPlugins]]
name = "user-manager"
addr = "127.0.0.1:8123"
path = "/frp/user"
ops = ["Login"]

[[httpPlugins]]
name = "port-manager"
addr = "127.0.0.1:8123"
path = "/frp/port"
ops = ["NewProxy"]
EOL

exec /usr/sbin/frps $@