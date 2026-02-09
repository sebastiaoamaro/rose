#!/bin/bash
cd /vagrant/schedules/reproduced_bugs/redpanda/lxc/scripts/
chmod +x *
sudo ./install.sh
sudo ./run_network.sh
sudo ./run_containers.sh
sudo ./test_jepsen.sh

cd /vagrant/schedules/reproduced_bugs/redisraft/lxc/
chmod +x *
sudo ./create_ssh_key.sh
sudo ./run_containers.sh dfd91d4
sudo ./test_jepsen.sh
