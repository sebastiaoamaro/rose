#!/bin/bash
workload_size=50000000
cd /vagrant/artifact_evaluation/tracing_overhead/throughput/
./run_ycsb.sh $workload_size /tmp/tracing_accuracy_test.out
