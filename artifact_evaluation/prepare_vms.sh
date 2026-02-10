#!/bin/bash
cd scripts/
./setup_anduril_vm.sh

# mkdir ~/shared/test2/
# vagrant up test2
# vagrant ssh test2 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
# vagrant ssh test2 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
# vagrant reload test2
# vagrant ssh test2 -c "cd /vagrant/artifact_evaluation && ./setup_dependencies.sh"
# vagrant reload test2
# vagrant ssh test2 -c "cd /vagrant/artifact_evaluation && ./setup_docker_systems.sh"
# vagrant reload test2
# vagrant halt test2

# mkdir ~/shared/test3/
# vagrant up test3
# vagrant ssh test3 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
# vagrant ssh test3 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
# vagrant reload test3
# vagrant ssh test3 -c "cd /vagrant/artifact_evaluation && ./setup_dependencies.sh"
# vagrant ssh test3 -c "cd /vagrant/artifact_evaluation && ./setup_lxc.sh"
# vagrant reload test3
# vagrant ssh test3 -c "cd /vagrant/artifact_evaluation && ./setup_lxc_systems.sh"
# vagrant halt test3


./setup_tracing_tests_vm.sh

# mkdir ~/shared/test5/
# vagrant up test5
# vagrant ssh test5 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
# vagrant ssh test5 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
# vagrant reload test5
# vagrant ssh test5 -c "cd /vagrant/artifact_evaluation && ./setup_lxc.sh"
# vagrant reload test5
# vagrant ssh test5 -c "cd /vagrant/artifact_evaluation && ./setup_lxc_systems.sh"
# vagrant ssh test5 -c "cd /vagrant/artifact_evaluation && ./setup_docker_systems.sh"
# vagrant reload test5
# vagrant halt test5
