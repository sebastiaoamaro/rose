#!/bin/bash
rm ~/shared/test3/*
vagrant up test3
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/tracing_overhead/throughput/ && ./overhead_test.sh 250000"
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/tracing_overhead/trace_size/ && python3 run.py"
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/tracing_overhead/ && python3 create_table.py"
vagrant halt test3 > /dev/null
