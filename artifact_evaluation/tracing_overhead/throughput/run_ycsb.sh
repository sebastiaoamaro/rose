#!/bin/bash
cd /vagrant/artifact_evaluation/tracing_overhead/throughput/ycsb-0.17.0
./bin/ycsb.sh load redis -P workloads/workloada -p recordcount=100000 -p "redis.host=172.38.0.11" -p "redis.port=6379" -p "redis.cluster=true" -p "redis.cluster.maxAttempts=50"
./bin/ycsb.sh run redis -P workloads/workloada -s -threads 8 -p status.interval=1 -p operationcount=$1 -p "redis.host=172.38.0.11" -p "redis.port=6379" -p "redis.cluster=true" -p "redis.cluster.maxAttempts=50" -s > $2.txt 2>&1 &
pid=$!
wait $pid
