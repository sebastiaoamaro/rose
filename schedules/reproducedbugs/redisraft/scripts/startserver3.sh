#!/bin/bash
echo "Restarting redis3"
docker compose -f /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/compose.yaml restart redis3
