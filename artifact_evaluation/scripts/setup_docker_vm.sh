#!/bin/bash
mkdir -p ~/shared/test2/
cd ../
vagrant up test2
vagrant ssh test2 -c "cd /vagrant/auxiliary_scripts && ./change_kernel.sh"
vagrant ssh test2 -c "cd /vagrant/auxiliary_scripts && ./resize.sh"
vagrant reload test2
vagrant ssh test2 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_dependencies.sh"
vagrant reload test2
vagrant ssh test2 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_redisraft.sh"
vagrant ssh test2 -c "cd /vagrant/artifact_evaluation/scripts/ && ./setup_mongo.sh"
vagrant halt test2
