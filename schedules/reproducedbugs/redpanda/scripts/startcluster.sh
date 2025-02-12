#!/bin/bash
echo 1048576 > /proc/sys/fs/aio-max-nr
cd /vagrant/rw/redpanda/
rm output.txt
docker compose -f configs/redpanda21.10.1.yml up -d
