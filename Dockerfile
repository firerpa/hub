FROM debian:bookworm-slim AS builder
LABEL maintainer="rev1si0n <lamda.devel@gmail.com>"

ADD . /tmp/build

ENV DEBIAN_FRONTEND=noninteractive
ENV OPENRESTY=/usr/local/openresty
ENV MIRROR=mirrors.tuna.tsinghua.edu.cn

ENV HOME=/user

COPY pip.conf           /etc

RUN bash /tmp/build/build-base.sh

# build ext desktop
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US.UTF-8
ENV LC_ALL=C
ENV DISPLAY_WIDTH=1600
ENV DISPLAY_HEIGH=900
ENV DISPLAY=:4096

RUN bash /tmp/build/build-desk.sh

# build main service
COPY nginx.conf         ${OPENRESTY}/nginx/conf

COPY redis.conf         /etc

COPY account.py         /usr/bin
COPY entry              /usr/bin

RUN bash /tmp/build/build-main.sh

RUN cd ~        && ls -A1 | xargs rm -rf
RUN cd /tmp     && ls -A1 | xargs rm -rf
RUN cd /root    && ls -A1 | xargs rm -rf
RUN rm -rf /var/lib/apt/lists/*

EXPOSE 8000 65000
WORKDIR                 /user
CMD [ "entry" ]

# stage 2
FROM scratch

ENV DEBIAN_FRONTEND=noninteractive
ENV OPENRESTY=/usr/local/openresty
ENV MIRROR=mirrors.tuna.tsinghua.edu.cn

ENV HOME=/user

ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US.UTF-8
ENV LC_ALL=C
ENV DISPLAY_WIDTH=1600
ENV DISPLAY_HEIGH=900
ENV DISPLAY=:4096

EXPOSE 8000 65000
WORKDIR                 /user
COPY --from=builder / /
CMD [ "entry" ]