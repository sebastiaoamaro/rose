#!/bin/bash
set -x
cd ../
mkdir -p ~/shared/test1/
vagrant up test1
vagrant ssh test1 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
vagrant ssh test1 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
vagrant reload test1
vagrant ssh test1 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_dependencies.sh"
vagrant ssh test1 -c "cd /vagrant/artifact_evaluation/scripts && ./setup_anduril.sh"
vagrant halt test1
