#!/bin/bash
cd /opt/redis/
./redis-server  --protected-mode no --bind 0.0.0.0 --dbfilename redis.rdb --loadmodule /opt/redis/redisraft.so raft-log-filename=raftlog.db loglevel=debug follower-proxy=yes raft-log-max-file-size=32000 raft-log-max-cache-size=1000000 >> /opt/redis/redis.log 2>&1
