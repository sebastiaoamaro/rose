#!/bin/bash
cd /vagrant/tests/redis/ycsb-0.17.0
./bin/ycsb.sh load mongodb -P workloads/workloada -p operationcount=$1 -p mongodb.url=mongodb://172.19.0.2:27017/ycsb
./bin/ycsb.sh run mongodb -P workloads/workloada -s -p status.interval=1 -p operationcount=$1 -p mongodb.url=mongodb://172.19.0.2:27017/ycsb -s > /vagrant/tests/mongo/results/$2.txt 2>&1
