#!/bin/bash
set -ex
cd $(dirname $0)

pip install --break-system-packages -r requirements.txt
pip install --break-system-packages driver-1.0.0-cp311-cp311-linux_$(arch).whl

# build server distribute
export PATH=${OPENRESTY}/luajit/bin:$PATH

luajit -b lua/ngx_op_api_gateway_validate.lua ${OPENRESTY}/nginx/ngx_op_api_gateway_validate.luac
luajit -b lua/ngx_op_webui_validate.lua ${OPENRESTY}/nginx/ngx_op_webui_validate.luac

cp -pr server   /usr/lib/python3/dist-packages
cp -pr executor /usr/lib/python3/dist-packages

# front static
mkdir -p /var/www; cp -pr html /var/www;

compile () {
    cythonize -b -i $@; rm $1 $(echo "$1" | sed 's/\.[^.]*$//').c ; strip -s $(echo "$1" | sed 's/\.[^.]*$//')*.so
}

pushd $(pwd)
cd /usr/lib/python3/dist-packages/server
compile              service.py
popd

pushd $(pwd)
cd /usr/lib/python3/dist-packages/executor
compile              queue.py
compile              event.py
compile              utils.py
compile              handlers/event.py
compile              config.py
popd

cp -pr pgbouncer.ini /etc
cp -pr mosquitto.conf /etc/mosquitto.conf
cp -pr frps.sh /usr/local/bin

cat <<EOL >/etc/supervisord.conf
[unix_http_server]
file=/run/service.sock
chmod=0700

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:///run/service.sock

[supervisord]
childlogdir=/run
minfds=262144
logfile=/dev/stdout
logfile_maxbytes=0
loglevel=error
nodaemon=true
silent=true
pidfile=/run/service.pid
user=root

[program:server]
numprocs                = 4
process_name            = %(program_name)s-%(process_num)s
command                 = python3 -u -m server --port=880%(process_num)s
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 1000

[program:event]
command                 = python3 -u -m executor
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 1000

[program:frps]
command                 = /usr/local/bin/frps.sh -c /etc/frps.toml
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 100

[program:edge]
command                 = python3 -u -m executor.edge
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 100

[program:auth]
command                 = python3 -u -m executor.auth
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 100

[program:cron]
command                 = python3 -u -m executor.cron
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 100

[program:mosquitto]
command                 = mosquitto -c /etc/mosquitto.conf
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/null
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 10

[program:pgbouncer]
user                    = nobody
command                 = /usr/local/bin/pgbouncer /etc/pgbouncer.ini
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 10

[program:openresty]
command                 = /usr/local/openresty/bin/openresty
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startretries            = 10000
priority                = 2000

[program:executor]
numprocs                = %(ENV_NPROC)s
process_name            = %(program_name)s-%(process_num)s
command                 = celery --app=executor.celery worker -l WARNING --pool gevent -n worker-%(process_num)02d@%%h --without-mingle --without-gossip
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 1000

[program:executor.beat]
command                 = celery --app=executor.celery beat -l INFO
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 1000

[group:service]
programs=openresty,server,executor,executor.beat,event,mosquitto,edge,cron,frps,auth,pgbouncer

[include]
files = /etc/supervisor/conf.d/*.conf
EOL