#!/bin/bash
rm ~/shared/test3/*
vagrant up test3
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/ && python3 run.py > /shared/heuristic_table.txt"
vagrant halt test3
