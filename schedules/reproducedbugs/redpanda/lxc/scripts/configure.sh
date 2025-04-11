#!/bin/bash
cd /vagrant/schedules/reproducedbugs/redpanda/lxc/scripts/
sudo rm /tmp/signal_start_workload.txt
touch /tmp/signal_start_workload.txt
./run_network.sh
./run_containers.sh
echo "Done creating containers"
