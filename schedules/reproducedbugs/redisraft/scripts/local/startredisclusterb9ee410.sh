#!/bin/bash
sudo rm -r /redis/*
cd /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft
docker compose -f setup/composeissue43.yaml up -d