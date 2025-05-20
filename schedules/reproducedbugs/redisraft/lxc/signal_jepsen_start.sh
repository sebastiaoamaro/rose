#!/bin/bash
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

echo "Process $PID detected. Waiting for termination or zombie state..."
while true; do
    # Check if the process is no longer running
    if ! ps -p "$PID" > /dev/null 2>&1; then
        echo "Process $PID has terminated."
        break
    fi

    # Check if the process is in a zombie state
    status=$(ps -o stat= -p "$PID" 2>/dev/null | cut -c 1)
    if [ "$status" = "Z" ]; then
        echo "Process $PID is in a zombie state (Z)."
        break
    fi

    sleep 1
done
echo "Process $PID has terminated"
