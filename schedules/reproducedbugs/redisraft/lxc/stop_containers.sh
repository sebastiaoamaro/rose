#!/bin/bash
n=5

for i in $(seq 1 $n); do
  lxc stop n${i};
  lxc delete n${i};
done

echo "Stopped and deleted 5 LXD containers"
