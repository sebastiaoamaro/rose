#!/bin/bash
vagrant up test4
vagrant ssh test4 -c "cd /vagrant/artifact_evaluation/tracing_overhead/throughput/ && ./overhead_test.sh"
vagrant ssh test4 -c "cd /vagrant/artifact_evaluation/tracing_overhead/trace_size/ && python3 run.py"
vagrant halt test4
