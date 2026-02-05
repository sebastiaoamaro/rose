#!/bin/bash
# vagrant up test1
# vagrant ssh test1 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
# vagrant ssh test1 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
# vagrant reload
#vagrant ssh test1 -c "cd /vagrant/artifact_evaluation && ./setup_dependencies.sh"

# vagrant up test2
# vagrant ssh test2 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
# vagrant ssh test2 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
# vagrant reload

vagrant ssh test2 -c "cd /vagrant/artifact_evaluation && ./setup_dependencies.sh"
