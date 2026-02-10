#!/bin/bash
rm ~/shared/test4/*
vagrant up test4
vagrant ssh test4 -c "cd /vagrant/artifact_evaluation/tracing_overhead/throughput/ && ./overhead_test.sh"
vagrant ssh test4 -c "cd /vagrant/artifact_evaluation/tracing_overhead/trace_size/ && python3 run.py"
vagrant ssh test4 -c "cd /vagrant/artifact_evaluation/tracing_overhead/ && python3 create_table.py"
vagrant halt test4 > /dev/null
