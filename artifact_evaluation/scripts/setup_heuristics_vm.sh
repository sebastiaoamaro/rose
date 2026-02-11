#!/bin/bash
mkdir ~/shared/test5/
vagrant up test5
vagrant ssh test5 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
vagrant ssh test5 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
vagrant reload test5
vagrant ssh test5 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_dependencies.sh"
vagrant reload test5
vagrant ssh test5 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_lxc.sh"
vagrant reload test5
vagrant ssh test5 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_lxc_systems.sh"
vagrant ssh test5 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_docker_systems.sh"
vagrant reload test5
vagrant halt test5
