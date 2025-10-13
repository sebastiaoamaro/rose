#!/bin/bash
# Start the script and wait for all subprocesses
#workload_size=50000000
#cd /vagrant/tests/redis
#./run_ycsb.sh $workload_size discovery_test.out

cd /vagrant/schedules/bug_discovery/redis_setup/
exec -a "$0" python3 client.py >> client.log 2>&1
