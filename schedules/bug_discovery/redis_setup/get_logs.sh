#!/bin/bash
# Define container names
containers=("node1" "node2" "node3")

# Directory to store the logs
log_dir="./logs"
mkdir -p "$log_dir"

# Log file for script output
log_file="container_logs.txt"
> "$log_file"  # Clear the log file if it exists

# Loop through each container and copy the output.log file
for container in "${containers[@]}"; do
    echo "Fetching server.log from $container..." | tee -a "$log_file"
    docker cp "$container:/server.log" "$log_dir/${container}_output.log" 2>>"$log_file"
    if [ $? -eq 0 ]; then
        echo "Successfully fetched server.log from $container." | tee -a "$log_file"
    else
        echo "Failed to fetch server.log from $container." | tee -a "$log_file"
    fi
done
