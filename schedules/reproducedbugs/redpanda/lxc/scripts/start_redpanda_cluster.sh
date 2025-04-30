#!/bin/bash
sudo kill -9 $(pgrep -f "/usr/bin/redpanda")
sudo rm /tmp/signal_start_workload.txt
export TERM=xterm
cd /vagrant/schedules/reproducedbugs/redpanda/lxc/scripts
sudo ./run_network.sh
for i in $(seq 1 $n); do
    lxc exec n${i} -n -- rm /var/lib/redpanda/data/pid.lock
	lxc file push redpanda.yaml n${i}/etc/redpanda/redpanda.yaml -q
	lxc exec n${i} -n -- kill -9 $(pgrep -f "/usr/bin/redpanda")
done
cd /vagrant/schedules/reproducedbugs/redpanda/lxc/redpanda_jepsen/
setsid lein run test --concurrency 1n --nodes-file /root/nodes --username root -s --time-limit 120 --test-count 1 > /tmp/jepsen.log 2>&1
