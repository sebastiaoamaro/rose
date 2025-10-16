#!/bin/bash
#exec -a "$0" strace -f -yy -e trace=write,open,openat -o strace.log redis-server /etc/redis/redis.conf >> server.log 2>&1 &
exec -a "$0" redis-server /etc/redis/redis.conf >> server.log 2>&1 &
pid=$!
wait $pid
