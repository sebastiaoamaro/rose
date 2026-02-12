#!/bin/bash
cd ../../
mkdir ~/shared/test3/
vagrant up test3
vagrant ssh test3 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
vagrant ssh test3 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
vagrant reload test3
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_dependencies.sh"
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_lxc.sh"
vagrant reload test3
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_lxc_systems.sh"
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/tracing_overhead/ && ./setup_redis.sh"
vagrant ssh test3 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_redisraft.sh"
vagrant halt test3
