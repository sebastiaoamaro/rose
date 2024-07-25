#!/bin/bash
echo "Restarting redis4"
docker compose -f /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/compose.yaml restart redis4
