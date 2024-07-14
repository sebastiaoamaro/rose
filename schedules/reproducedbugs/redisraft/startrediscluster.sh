#!/bin/bash
sudo rm -r /redis/*
cd /home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft
docker compose -f compose.yaml up -d
# Define the command or script to run in each "redis" container
COMMAND="./initcluster.sh"
sleep 5
# Loop through each container with the name "redis"
for container in $(docker ps --filter "name=redis" --format "{{.ID}}"); do
  echo "Running command in container $container"
  docker exec "$container" $COMMAND
done