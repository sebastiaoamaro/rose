#!/bin/bash
echo "GO" > /tmp/signal_start_workload.txt
PID_FILE="/tmp/jepsen_pid"
echo "Waiting for PID file to be created..."
while [ ! -f "$PID_FILE" ]; do
    sleep 0.5
done

echo "PID file found, waiting for PID..."
while [ ! -s "$PID_FILE" ]; do
    sleep 0.5
done

PID=$(cat "$PID_FILE" | tr -d '[:space:]')
if ! [[ "$PID" =~ ^[0-9]+$ ]]; then
    echo "Error: Invalid PID format in $PID_FILE"
fi

echo "Waiting for process $PID to start..."
while ! ps aux | grep -w "$PID" | grep -v grep > /dev/null; do
    sleep 0.5
done

echo "Process $PID detected, waiting for termination..."
while ps aux | grep -w "$PID" | grep -v grep > /dev/null; do
    sleep 1
done

echo "Process $PID has terminated"
