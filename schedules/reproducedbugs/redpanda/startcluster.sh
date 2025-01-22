#!/bin/bash
cd /home/sebastiaoamaro/phd/torefidevel/rw/redpanda/
rm output.txt
docker compose -f configs/redpanda21.10.1.yml up >> output.txt &

# sleep 5

# SCRIPT_TO_RUN="./rpksetup.sh"

# # Check if the script exists
# if [ ! -f "$SCRIPT_TO_RUN" ]; then
#     echo "Error: Script $SCRIPT_TO_RUN not found."
#     exit 1
# fi

# # Get all container IDs with "redpanda" in their name
# CONTAINERS=$(docker ps --filter "name=redpanda" --format "{{.ID}}")

# # Check if there are any matching containers
# if [ -z "$CONTAINERS" ]; then
#     echo "No containers with 'redpanda' in the name are running."
#     exit 0
# fi

# # Loop through each container and run the script
# for CONTAINER in $CONTAINERS; do
#     echo "Running script in container $CONTAINER..."
    
#     # Execute the script inside the container
#     docker exec $CONTAINER $SCRIPT_TO_RUN
# done

# echo "Script executed for all matching containers."
