#!/bin/bash

# Ensure a filename is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <output_file>"
    exit 1
fi

# Clear the output file
rm -f "$1"
touch "$1"

# lxc list status=running --format csv -c n,p,volatile.eth0.host_name
result=$(lxc list status=running --format csv -c n,p,volatile.eth0.host_name)

# Cycle through the lines in result and add ppid according to the inter_result pid
while IFS=, read -r name pid host_name; do
    ppid=$(pstree -p "$pid" | grep -o 'redpanda([0-9]\+)' | cut -d'(' -f2 | cut -d')' -f1)
    iflink=$(lxc exec "$name" -n -- cat /sys/class/net/eth0/iflink)

    # echo "name: $name, pid: $pid, iflink: $iflink, ppid: $ppid, host_name: $host_name"
    echo "$name,$pid,$ppid,$iflink,$host_name" >> "$1"
done <<< "$result"

# echo "Output written to $1"