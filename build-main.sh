#!/bin/bash
set -ex
cd $(dirname $0)

pip install --break-system-packages -r requirements.txt
pip install --break-system-packages driver-1.0.0-cp311-cp311-linux_x86_64.whl

# build server distribute
pushd $(pwd)
cd server
export PATH=${OPENRESTY}/luajit/bin:$PATH

luajit -b script/ngx_novnc.lua ${OPENRESTY}/nginx/ngx_novnc.luac
luajit -b script/ngx_validate.lua ${OPENRESTY}/nginx/ngx_validate.luac
luajit -b script/ngx_control.lua ${OPENRESTY}/nginx/ngx_control.luac

cythonize -b -i                 models.py
cythonize -b -i                 utils.py
cythonize -b -i                 service.py
strip -s *.so

rm $0
rm -rf script/
rm {models,utils,service}.{py,c}
popd

mv server/start.sh /usr/bin
cp -pr server /usr/lib/python3/dist-packages

cp -pr mosquitto.conf /etc/mosquitto

cat <<EOL >/etc/supervisord.conf
[unix_http_server]
file=/run/service.sock
username=lamda
password=lamda
chmod=0700

[rpcinterface:main]
supervisor.rpcinterface_factory=supervisor.rpcinterface:make_main_rpcinterface

[supervisord]
childlogdir=/run
logfile=/dev/stdout
logfile_maxbytes=0
loglevel=error
nodaemon=true
silent=true
pidfile=/run/service.pid
user=root

[program:redis]
command                 = redis-server /etc/redis.conf
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/null
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 5
startretries            = 10000
priority                = 10

[program:server]
command                 = bash /usr/bin/start.sh
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
command                 = mosquitto -c /etc/mosquitto/mosquitto.conf
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startsecs               = 10
startretries            = 10000
priority                = 5000

[program:openresty]
command                 = /usr/local/openresty/bin/openresty
autostart               = true
autorestart             = true
stderr_logfile          = /dev/null
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
startretries            = 10000
priority                = 1000

[group:service]
programs=openresty,server,redis

[include]
files = /etc/supervisor/conf.d/*.conf
EOL