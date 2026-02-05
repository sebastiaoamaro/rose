#!/bin/bash
trap 'echo Received SIGTERM' SIGTERM
trap 'echo Received SIGKILL' SIGINT
sudo rm /tmp/jepsen_pid
sudo rm /tmp/signal_start_workload.txt
sudo rm -r /vagrant/schedules/reproduced_bugs/redpanda/lxc/redpanda_jepsen/store/*
/vagrant/auxiliary_scripts/change_java.sh 17
export TERM=xterm
cd /vagrant/schedules/reproduced_bugs/redpanda/lxc/scripts
sudo sh -c 'echo 2097152 > /proc/sys/fs/aio-max-nr'
for i in $(seq 1 5); do
    lxc exec n${i} -n -- rm /var/lib/redpanda/data/pid.lock
	lxc file push redpanda.yaml n${i}/etc/redpanda/redpanda.yaml -q
	lxc exec n${i} -n -- kill -9 $(pgrep -f "/usr/bin/redpanda")
done
cd /vagrant/schedules/reproduced_bugs/redpanda/lxc/redpanda_jepsen/

echo "go" >> /tmp/signal_start_workload.txt
lein run test --concurrency 4n --nodes-file /root/nodes --username root -s --time-limit 90 --test-count 1
