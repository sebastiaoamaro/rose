#!/bin/bash
sudo rm -r /redis/*
cd /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft
docker compose -f composeissue43.yaml up -d