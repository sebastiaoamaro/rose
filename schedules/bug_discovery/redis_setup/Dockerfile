
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y locales \
    && locale-gen en_US.UTF-8 \
    && update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

RUN apt-get update && \
    apt-get install -y \
    strace \
    iproute2 \
    net-tools \
    procps \
    iputils-ping \
    wget \
    build-essential \
    tcl

RUN wget https://download.redis.io/releases/redis-8.0.3.tar.gz && \
    tar xzf redis-8.0.3.tar.gz && \
    cd redis-8.0.3 && \
    make && \
    make install && \
    cd .. && \
    rm -rf redis-8.0.3*

RUN mkdir /scripts
WORKDIR /scripts
COPY start_redis.sh /scripts/
RUN chmod +x /scripts/start_redis.sh
