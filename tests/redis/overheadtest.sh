#!/bin/bash
workload_size=5000000
#workload_size=500000
runs=1
# maindirectory=/home/sebastiaoamaro/phd/torefidevel/rosetracer/
# main=/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer
maindirectory=/vagrant/rosetracer/
main=/vagrant/rosetracer/target/release/rosetracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $maindirectory
#bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
cd $SCRIPT_DIR

chmod +x configs/setup.sh
chmod +x runycsb.sh

sudo rm -r /redis/*

ulimit -n 4096
#rm results/*
for topology in 3
do
    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        #sudo /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/setup.sh $topology
        #Normal run
        docker compose -f configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes
        sleep 30

        echo Starting Workload
        #/usr/bin/time -ao stats/times$date.txt -f "$run:v:$topology:%e" ./ycsb.sh $workload_size topology$topology:$run
        #sudo perf record -ag -o vanilla.perf &
        #perf_pid=$!
        ./ycsb.sh $workload_size topology$topology:$run
        #sudo kill -2 $perf_pid
        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /redis/*
    done

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    container_and_pid="container_and_pid.txt"
    container_names="container_names.txt"
    functions_file="../../tracertests/functions.txt"
    file="check.txt"

    binary_path="/usr/local/bin/redis-server"

    sudo rm $file
    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        #sudo /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/setup.sh $topology
        docker compose -f configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes
        sleep 30

        ./retrievecontainerinfo.sh $container_and_pid
        sudo $main "production_tracer" "container" $functions_file $binary_path $container_and_pid "none" &

        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload

        #sudo perf record -ag -o tracing.perf &
        #perf_pid=$!
        ./runycsb.sh $workload_size tracerontopology$topology:$run

        #sudo kill -2 $perf_pid

        sudo kill -2 $ebpf_PID
        docker compose -f configs/docker-compose$topology.yaml down
        cp /tmp/history.txt results/history$topology:$run.txt
        sudo rm -r /redis/*
    done

done

reset
#cd stats
#./generate_graphs.sh perfomance times$date.txt
