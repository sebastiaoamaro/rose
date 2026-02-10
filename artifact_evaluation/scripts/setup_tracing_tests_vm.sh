#!/bin/bash
cd ../../
mkdir ~/shared/test4/
vagrant up test4
vagrant ssh test4 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
vagrant ssh test4 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
vagrant reload test4
vagrant ssh test4 -c "cd /vagrant/artifact_evaluation && ./setup_dependencies.sh"
vagrant ssh test4 -c "cd /vagrant/artifact_evaluation/tracing_overhead && ./setup_redis.sh"
vagrant halt test4
