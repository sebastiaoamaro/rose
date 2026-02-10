#!/bin/bash
cd ..
vagrant up test1
vagrant ssh test1 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py scf_bugs.txt"
vagrant halt test1

vagrant up test2
vagrant ssh test2 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py docker_bugs.txt"
vagrant halt test2

vagrant up test3
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py lxc_bugs.txt"
vagrant halt test3
