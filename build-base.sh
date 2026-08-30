#!/bin/bash
set -ex
OPENRESTYVER=1.25.3.2
cd $(dirname $0)

sed -i "s/deb.debian.org/${MIRROR}/g" /etc/apt/sources.list.d/debian.sources

apt update && apt upgrade -y
apt install -y zlib1g-dev libperl-dev libpcre3-dev libssl-dev libffi-dev wget gcc g++ make curl pkg-config pandoc libcurl4-openssl-dev libedit-dev libevent-dev libmicrohttpd-dev libsqlite3-dev libcjson-dev libwebsockets-dev
apt install -y supervisor python3 python3-dev python3-pip

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

# pgbouncer
pushd $(pwd)
wget https://github.com/pgbouncer/pgbouncer/releases/download/pgbouncer_1_25_2/pgbouncer-1.25.2.tar.gz -O - | tar -xz
cd pgbouncer-1.25.2 && ./configure && make -j8 install
popd

pushd $(pwd)
wget https://github.com/jpmens/mosquitto-auth-plug/archive/refs/tags/0.1.3.tar.gz -O - | tar -xz
wget https://github.com/eclipse-mosquitto/mosquitto/archive/refs/tags/v2.1.2.tar.gz -O - | tar -xz

pushd $(pwd)
PATCH=$(pwd)/mosquitto-auth-plug.patch
cd mosquitto-auth-plug-0.1.3
patch -f -p1 <$PATCH
popd

pushd $(pwd)
PATCH=$(pwd)/mosquitto.patch
cd mosquitto-2.1.2
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

MOSQUITTO_SRC = $(pwd)/mosquitto-2.1.2
SUPPORT_DJANGO_HASHERS ?= no
CFG_CFLAGS = -I$(pwd)/mosquitto-2.1.2/include
CFG_LDFLAGS = -lcurl -ldl
EOL

pushd $(pwd)
cd mosquitto-2.1.2; make WITH_WEBSOCKETS=yes -j8 || true
popd

echo '#include <mosquitto.h>'  >mosquitto-2.1.2/include/mosquitto_plugin.h
echo '#include <mosquitto.h>'  >mosquitto-2.1.2/include/mosquitto_broker.h

pushd $(pwd)
cd mosquitto-auth-plug-0.1.3; make -j8 || true
popd

cp -pr mosquitto-2.1.2/src/mosquitto /usr/sbin
cp -pr mosquitto-2.1.2/client/mosquitto_* /usr/bin

cp -pr mosquitto-auth-plug-0.1.3/auth-plug.so /usr/lib/mosquitto-auth-plug.so
cp -pr mosquitto-2.1.2/mosquitto.conf /etc/mosquitto.conf
cp -pr mosquitto-2.1.2/lib/libmosquitto.so.1 /usr/lib
popd

# frps
pushd $(pwd)
FRP_VERSION="0.71.0"
UNAME=$(uname -m)
case "$UNAME" in
x86_64)    ARCH="amd64" ;;
aarch64)   ARCH="arm64" ;;
armv7l)    ARCH="arm"   ;;
riscv64)   ARCH="riscv64" ;;
i386|i686) ARCH="386"   ;;
*)         ARCH="$UNAME" ;;
esac
FILENAME="frp_${FRP_VERSION}_linux_${ARCH}.tar.gz"
URL="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${FILENAME}"
wget -qO- "$URL" | tar -xzv --strip-components=1 "frp_${FRP_VERSION}_linux_${ARCH}/frps"

chmod 755 frps
cp frps /usr/sbin/frps
popd