#!/bin/bash
./runschedule.sh schedules/reproducedbugs/redisraft/redis_bug_43.yaml
docker compose -f schedules/reproducedbugs/redisraft/composeissue43.yaml down