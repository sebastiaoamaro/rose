#!/bin/bash
workload_size=10000000
#workload_size=100000
runs=3
# maindirectory=/home/sebastiaoamaro/phd/torefidevel/rosetracer/
# main=/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer
maindirectory=/vagrant/rosetracer/
main=/vagrant/rosetracer/target/release/rosetracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $maindirectory
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
cd $SCRIPT_DIR

chmod +x configs/setup.sh
chmod +x runycsb.sh

sudo rm -r /redis/*

ulimit -n 4096
#rm results/*
for topology in 3 6 12
do
    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology

        #Normal run
        docker compose -f configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes
        sleep 30

        echo Starting Workload
        ./run_ycsb.sh $workload_size topology$topology:$run
        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /redis/*
    done

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    container_info="container_and_pid.txt"
    functions_file="../../tracertests/functions.txt"
    file="check.txt"
    binary_path="/usr/local/bin/redis-server"

    sudo rm $file
    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        docker compose -f configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes
        sleep 30

        ./retrieve_container_info.sh $container_info
        sudo $main "production_trace,container" $functions_file $binary_path $container_info "none" &

        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload
        ./run_ycsb.sh $workload_size tracerontopology$topology:$run

        sudo kill -2 $ebpf_PID

        wait $ebpf_PID
        docker compose -f configs/docker-compose$topology.yaml down
        sudo mv /tmp/history.txt results/history$topology:$run.txt
        sudo rm -r /redis/*
    done

done

reset
#cd stats
#./generate_graphs.sh perfomance times$date.txt
