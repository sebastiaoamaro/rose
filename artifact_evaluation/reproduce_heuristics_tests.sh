#!/bin/bash
rm ~/shared/test5/*
vagrant up test5
vagrant ssh test5 -c "cd /vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/ && python3 run.py"
vagrant halt test5
