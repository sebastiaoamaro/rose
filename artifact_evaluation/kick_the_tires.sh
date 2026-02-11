#!/bin/bash
rm ~/shared/test1/*
rm ~/shared/test2/*
rm ~/shared/test3/*
vagrant up test1
vagrant ssh test1 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py kick_the_tires_scf.txt"
vagrant halt test1 > /dev/null

vagrant up test2
vagrant ssh test2 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py kick_the_tires_docker.txt"
vagrant halt test2 > /dev/null

vagrant up test3
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py kick_the_tires_lxc.txt"
vagrant halt test3 > /dev/null

vagrant up test3
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/tracing_overhead/throughput/ && ./overhead_test.sh 250000"
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/tracing_overhead/trace_size/ && python3 run.py"
vagrant halt test3 > /dev/null
