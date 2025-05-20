#!/bin/bash

# Get IPv4 addresses on interface 'eth0'
for container in $(lxc list -c n --format csv); do
    ip=$(lxc list "$container" -c 4 --format csv | grep 'eth0' | awk -F '[ ,]+' '{print $1}')
    [ -n "$ip" ] && echo "$container: $ip"
done
