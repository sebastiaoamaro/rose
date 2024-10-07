#!/bin/bash
sudo rm -r /redis/*
cd /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft
docker compose -f composeissue43.yaml up -d


docker exec -dt redis1 ./startredis.sh 1 172.19.1.10
docker exec -dt redis2 ./startredis.sh 2 172.19.1.11
docker exec -dt redis3 ./startredis.sh 3 172.19.1.12
docker exec -dt redis4 ./startredis.sh 4 172.19.1.13
docker exec -dt redis5 ./startredis.sh 5 172.19.1.14

sleep 15