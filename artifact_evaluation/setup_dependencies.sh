#!/bin/bash
cd /vagrant/auxiliary_scripts/
./install.sh
cd /vagrant/rw/Anduril/
./install.sh/
cd /vagrant/auxiliary_scripts/
./build_anduril_systems.sh
cd /vagrant/schedules/reproduced_bugs/redisraft/setup/
./build_images.sh
cd /vagrant/schedules/reproduced_bugs/mongo/mongo_2.4.3/scripts/
./build_images.sh

# cd /vagrant/schedules/redpanda/lxc/scripts/
# ./install.sh
# ./run_containers.sh
# ./run_network.sh
# ./test_jepsen.sh
# cd /vagrant/schedules/redisraft/lxc/
# ./install.sh
# ./run_containers.sh
# ./run_network.sh
# ./test_jepsen.sh
