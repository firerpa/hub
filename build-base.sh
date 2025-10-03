#!/bin/bash
set -ex
OPENRESTYVER=1.25.3.2
cd $(dirname $0)

sed -i "s/deb.debian.org/${MIRROR}/g" /etc/apt/sources.list.d/debian.sources

apt update && apt upgrade -y
apt install -y zlib1g-dev libperl-dev libpcre3-dev libssl-dev libffi-dev wget gcc g++ make iperf3 curl libcurl4-openssl-dev libcjson-dev
apt install -y supervisor redis python3 python3-dev python3-pip

mkdir -p ${HOME}

# openresty
pushd $(pwd)
wget https://openresty.org/download/openresty-${OPENRESTYVER}.tar.gz -O - | tar -xz
cd openresty-${OPENRESTYVER} && ./configure --with-http_v2_module && make -j8 install

wget https://github.com/ledgetech/lua-resty-http/archive/refs/tags/v0.17.2.tar.gz -O - | tar -xz
cp -pr lua-resty-http-0.17.2/lib/resty/http*.lua /usr/local/openresty/lualib/resty
wget https://github.com/fffonion/lua-resty-openssl/archive/refs/tags/1.2.1.tar.gz -O - | tar -xz
cp -pr lua-resty-openssl-1.2.1/lib/resty/* /usr/local/openresty/lualib/resty
popd

pushd $(pwd)
wget https://github.com/jpmens/mosquitto-auth-plug/archive/refs/tags/0.1.3.tar.gz -O - | tar -xz
wget https://github.com/eclipse-mosquitto/mosquitto/archive/refs/tags/v2.0.22.tar.gz -O - | tar -xz

pushd $(pwd)
PATCH=$(pwd)/mosquitto-auth-plug.patch
cd mosquitto-auth-plug-0.1.3
patch -f -p1 <$PATCH
popd

cat <<EOL >mosquitto-auth-plug-0.1.3/config.mk
BACKEND_CDB ?= no
BACKEND_MYSQL ?= no
BACKEND_SQLITE ?= no
BACKEND_REDIS ?= no
BACKEND_POSTGRES ?= no
BACKEND_LDAP ?= no
BACKEND_HTTP ?= yes
BACKEND_JWT ?= no
BACKEND_MONGO ?= no
BACKEND_FILES ?= no
BACKEND_MEMCACHED ?= no

MOSQUITTO_SRC = $(pwd)/mosquitto-2.0.22
SUPPORT_DJANGO_HASHERS ?= no
CFG_CFLAGS = -I$(pwd)/mosquitto-2.0.22/include
CFG_LDFLAGS = -lcurl -ldl
EOL

pushd $(pwd)
cd mosquitto-2.0.22; make -j8 || true
popd

pushd $(pwd)
cd mosquitto-auth-plug-0.1.3; make -j8 || true
popd

cp -pr mosquitto-2.0.22/src/mosquitto /usr/sbin
cp -pr mosquitto-2.0.22/client/mosquitto_* /usr/bin
mkdir -p /etc/mosquitto/plugins

cp -pr mosquitto-auth-plug-0.1.3/auth-plug.so /etc/mosquitto/plugins
cp -pr mosquitto-2.0.22/mosquitto.conf /etc/mosquitto
cp -pr mosquitto-2.0.22/lib/libmosquitto.so.1 /usr/lib
popd