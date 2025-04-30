#!/bin/bash
cd /vagrant/schedules/reproducedbugs/redpanda/lxc/scripts/
sudo rm /tmp/signal_start_workload.txt
touch /tmp/signal_start_workload.txt
sudo ./run_network.sh
sudo ./run_containers.sh
echo "Done creating containers"
echo "GO" > /tmp/signal_start_workload.txt
sudo ./start_redpanda_cluster.sh &
