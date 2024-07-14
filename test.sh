#!/bin/bash
./runschedule.sh schedules/reproducedbugs/redisraft/redis_test2.yaml
docker compose -f schedules/reproducedbugs/redisraft/compose.yaml down