#!/bin/bash
echo "Restarting redis2"
docker compose -f /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/compose.yaml restart redis2
