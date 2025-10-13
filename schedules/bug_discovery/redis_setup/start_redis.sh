#!/bin/bash
exec -a "$0" strace -ff -e trace=write -o strace.log redis-server /etc/redis/redis.conf >> server.log 2>&1 &
#exec -a "$0" redis-server /etc/redis/redis.conf >> server.log 2>&1 &
pid=$!
wait $pid
