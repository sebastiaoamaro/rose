#!/bin/bash
workload_size=2500000
maindirectory=/home/sebastiaoamaro/phd/torefidevel/rosetracer/
main=/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer
# maindirectory=/vagrant/rosetracer/
# main=/vagrant/rosetracer/target/release/rosetracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $maindirectory
cargo build --release
cd $SCRIPT_DIR

sudo rm -r /redis/*

#Tracing active
container_and_pid="container_and_pid.txt"
functions_file="functions.txt"
file="check.txt"
probe_stats="/tmp/uprobe_stats.txt"

setup="/home/sebastiaoamaro/phd/torefidevel/tracertests/redis/setup.sh 3"
workload="/home/sebastiaoamaro/phd/torefidevel/tracertests/redis/runworkload.sh $workload_size 3 0"
cleanup="/home/sebastiaoamaro/phd/torefidevel/tracertests/redis/cleanup.sh 3"
binary_path="/usr/local/bin/redis-server"


chmod +x $setup
chmod +x $workload
chmod +x $cleanup

sudo rm $file
sudo rm $probe_stats

#sudo /vagrant/tests/redis/configs/setup.sh $topology

$setup
./retrievecontainerinfo.sh $container_and_pid
sudo $main "stats_tracer" $functions_file $binary_path $container_and_pid &
ebpf_PID=$!

#Wait until ebpf is setup
while [ ! -s "$file" ]; do
    #echo "File is empty or does not exist. Waiting..."
    sleep 1  # Wait for 5 seconds before checking again
done

echo Starting Workload

SECONDS=0
$workload
elapsed_time=$SECONDS

echo Sent -2 to $ebpf_PID
sudo kill -2 $ebpf_PID

$cleanup

reset

