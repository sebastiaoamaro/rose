#!/bin/bash
cd /vagrant/schedules/bug_discovery/redis_setup/
./get_logs.sh
logs=$(timeout 1 sudo bpftool prog tracelog)
echo "$logs" > bpf_logs.txt
docker compose -f docker-compose.yaml down
