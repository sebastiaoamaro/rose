#!/bin/bash

# Get the list of all running container IDs
container_ids=$(docker ps -q)

# Loop through each container ID and display its logs
for container_id in $container_ids; do
  echo "Logs for container ID: $container_id"
  docker exec -ti $container_id cat output.log
  echo "---------------------------------------------"
done