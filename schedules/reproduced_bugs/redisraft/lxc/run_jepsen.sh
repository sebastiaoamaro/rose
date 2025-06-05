#!/bin/bash
trap 'echo Received SIGTERM' SIGTERM
trap 'echo Received SIGKILL' SIGINT
rm /tmp/signal_start_workload.txt
rm /tmp/jepsen_pid
rm -r /vagrant/schedules/reproduced_bugs/redisraft/lxc/redis/store/*
for i in $(seq 1 $n); do
    lxc exec n${i} -n -- rm /opt/redis/redis.pid
done
cd /vagrant/schedules/reproduced_bugs/redisraft/lxc/redis
setsid lein run test-all --nemesis none --time-limit 60 --test-count 1 --username root --concurrency 25n --nodes-file /home/vagrant/nodes  --ssh-private-key /home/vagrant/.ssh/id_rsa > /tmp/jepsen.log 2>&1 &
pid=$!
echo $pid > /tmp/jepsen_pid
wait $pid
