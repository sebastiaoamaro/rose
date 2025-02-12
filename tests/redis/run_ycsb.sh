#!/bin/bash
cd ycsb-0.17.0
./bin/ycsb.sh load redis -P workloads/workloada -p operationcount=$1 -p "redis.host=172.38.0.11" -p "redis.port=6379" -p "redis.cluster=true"
./bin/ycsb.sh run redis -P workloads/workloada -s -p status.interval=1 -p operationcount=$1 -p "redis.host=172.38.0.11" -p "redis.port=6379" -p "redis.cluster=true" -s > ../results/$2.txt 2>&1
