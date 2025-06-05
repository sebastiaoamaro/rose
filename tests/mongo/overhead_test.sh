#!/bin/bash
workload_size=500000
runs=3
maindirectory=/vagrant/tracer/
main=/vagrant/tracer/target/release/tracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $maindirectory
#bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
cd $SCRIPT_DIR

ulimit -n 4096
sudo rm -r /mongo/*
for topology in 4 8 16
do
    for (( run=1; run<=$runs; run++ ))
        do
        #Normal run
        docker compose -f configs/docker-compose$topology.yaml up -d
        chmod +x configs/start$topology.sh
        sleep 15
        mongo0name=$(docker ps -aqf "name=mongo0")
        docker exec -d $mongo0name ./rs-init.sh

        echo Starting Workload
        ./run_ycsb.sh $workload_size topology$topology:$run

        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /mongo/*
        done

############################################################################################################
############################################################################################################
############################################################################################################
    container_info="container_and_pid.txt"
    functions_file="functions.txt"
    binary_path="/usr/bin/mongo"
    file="check.txt"

    sudo rm $file
    #Tracing active
    for (( run=1; run<=$runs; run++ ))
        do
        docker compose -f configs/docker-compose$topology.yaml up -d
        sleep 30

        ebpf_PID=$!
        echo $ebpf_PID

        mongo0name=$(docker ps -aqf "name=mongo0")
        docker exec -d $mongo0name ./rs-init.sh

        ./retrieve_container_info.sh $container_info
        sudo $main "production_trace,container" $functions_file $binary_path $container_info "none" &
        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            sleep 1
        done
        echo Starting Workload
        ./run_ycsb.sh $workload_size tracerontopology$topology:$run

        kill -2 $ebpf_PID
        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /mongo/*
        done

done

#cd stats
#./generate_graphs.sh perfomance times$date.txt
