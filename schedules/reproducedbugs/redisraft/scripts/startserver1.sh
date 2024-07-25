#!/bin/bash
echo "Restarting redis1"
docker compose -f /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/compose.yaml restart redis1
