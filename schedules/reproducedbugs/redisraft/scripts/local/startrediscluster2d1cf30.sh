#!/bin/bash
sudo rm -r /redis/*
cd /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft
docker compose -f setup/composeissue51.yaml up -d