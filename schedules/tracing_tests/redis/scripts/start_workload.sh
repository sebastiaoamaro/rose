#!/bin/bash
workload_size=10000000
cd /vagrant/tests/redis
./run_ycsb.sh $workload_size tracing_accuracy_test.out
