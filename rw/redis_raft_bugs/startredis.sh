#!/bin/bash
echo "I am in script, arg1 is: $1, arg2 is: $2, arg3 is: $3" 

# Check if the argument is a valid number
if ! [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "The argument is not a valid number."
    exit 1
fi

exec -a "$0" /redis-server \
    --bind 0.0.0.0 \
    --port 5001 \
    --dbfilename raft$1.rdb \
    --protected-mode no \
    --loadmodule ./redisraft.so \
    raft-log-filename=raftlog$1.db addr=$2:5001 loglevel=debug follower-proxy=yes raft-log-max-file-size=32000 raft-log-max-cache-size=1000000 >> output.log 2>&1 &

pid=$!
#sleep 10
file_path="output.log"

while [ ! -e "$file_path" ]; do
  echo "Waiting for $FILE to be created..." >> control.log
  sleep 1  # Check every 1 second
done

while [[ $(wc -l < "$file_path") -lt 10 ]]; do
    echo "Waiting for the file to have at least 10 lines..." >> control.log
    sleep 1  # Wait for 1 second before checking again
done

if [ "$1" -eq 1 ]; then
    echo "Creating cluster" >> $file_path
    ./redis-cli -p 5001 raft.cluster init >> $file_path
    #./redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes
else
    echo "Joining cluster" >> $file_path
    ./redis-cli -p 5001 RAFT.CLUSTER JOIN 172.19.1.10:5001 >> $file_path
fi

# # Loop to check if the process is still running
# while kill -0 $pid_to_wait 2>/dev/null; do
#     sleep 1
# done

wait $pid

