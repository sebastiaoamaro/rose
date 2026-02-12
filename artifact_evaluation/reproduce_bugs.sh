#!/bin/bash
cd ..
vagrant up test1
vagrant ssh test1 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py scf_bugs.txt"

#ZK 4203 only shows in scenarios where the cpu is overloaded, we emulate this by reducing the number of cores
cd ../auxiliary_scripts/ && ./change_cores.sh 1 && cd ..
vagrant reload test1
vagrant ssh test1 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py zk_4203.txt"
vagrant halt test1
cd ../auxiliary_scripts/ && ./change_cores.sh 8 && cd ..

vagrant up test2
vagrant ssh test2 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py docker_bugs.txt"
vagrant halt test2

vagrant up test3
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/bug_reproduction/ && python3 run.py lxc_bugs.txt"
vagrant halt test3
