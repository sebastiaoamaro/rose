#!/bin/bash
n=5

for i in $(seq 1 $n); do
  lxc stop n${i}redis;
  lxc delete n${i}redis;
done

echo "Stopped and deleted 5 LXD containers"
