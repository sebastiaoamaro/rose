#!/bin/bash
docker compose -f /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/docker-compose$1.yaml down
sudo rm -r /redis/*