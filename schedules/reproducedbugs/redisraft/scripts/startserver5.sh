#!/bin/bash
echo "Restarting redis5"
docker compose -f /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/compose.yaml restart redis5
