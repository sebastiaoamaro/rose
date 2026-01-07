#!/bin/bash
n=5

for i in $(seq 1 $n); do
  lxc restart n${i};
done

echo "Restarted 5 containers"
