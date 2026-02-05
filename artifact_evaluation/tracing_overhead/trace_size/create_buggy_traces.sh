#!/bin/bash
cd /vagrant/
./run_reproduction.sh /schedules/tracing_tests/redis/schedules/full_trace_faults.yaml
sudo mv /tmp/history.txt /schedules/tracing_tests/redis/traces/history_full.txt

./run_reproduction.sh /schedules/tracing_tests/redis/schedules/full_trace_faults.yaml
sudo mv /tmp/history.txt /schedules/tracing_tests/redis/traces/history_full.txt

./run_reproduction.sh /schedules/tracing_tests/redis/schedules/full_trace_faults.yaml
sudo mv /tmp/history.txt /schedules/tracing_tests/redis/traces/history_full.txt
