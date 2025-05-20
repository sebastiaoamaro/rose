#!/bin/bash
cd /vagrant/tests/redis/ycsb-0.17.0
./bin/ycsb.sh load redis -P workloads/workloada -p recordcount=100000 -p "redis.host=172.38.0.11" -p "redis.port=6379" -p "redis.cluster=true"
./bin/ycsb.sh run redis -P workloads/workloada -s -threads 8 -p status.interval=1 -p operationcount=$1 -p "redis.host=172.38.0.11" -p "redis.port=6379" -p "redis.cluster=true" -s > /vagrant/tests/redis/results/$2.txt 2>&1 &
pid=$!
wait $pid
