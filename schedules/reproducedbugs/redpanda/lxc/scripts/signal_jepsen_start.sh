#!/bin/bash
echo "GO" > /tmp/signal_start_workload.txt
FILE="/vagrant/schedules/reproducedbugs/redpanda/lxc/redpanda_jepsen/store/current/results.edn"
rm -f $FILE
echo "Waiting for $FILE to be created..."

while [ ! -f "$FILE" ]; do
    sleep 1  # Check every 1 second
done

echo "$FILE detected. Exiting."
exit 0
