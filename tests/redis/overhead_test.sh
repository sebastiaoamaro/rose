#!/bin/bash
workload_size=25000000
#workload_size=250000
runs=5
maindirectory=/vagrant/tracer/
main=/vagrant/tracer/target/release/tracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $maindirectory
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
cd $SCRIPT_DIR
sudo rm -r /redis/*

ulimit -n 4096
#rm results/*
for topology in 3
do
    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        #Normal run
        docker compose -f  /vagrant/tests/redis/configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat /vagrant/tests/redis/configs/ips$topology.txt) --cluster-yes
        sleep 30

        echo Starting Workload
        /vagrant/tests/redis/run_ycsb.sh $workload_size vanilla$topology:$run
        docker compose -f  /vagrant/tests/redis/configs/docker-compose$topology.yaml down
        sudo rm -r /redis/*
    done

############################################################################################################
############################################################################################################
############################################################################################################

    #SysAll Tracer Active
    container_info="/vagrant/tests/redis/container_and_pid.txt"
    functions_file="/vagrant/profiler/redis/functions.txt"
    file="check.txt"
    binary_path="/usr/local/bin/redis-server"

    sudo rm $file
    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        docker compose -f /vagrant/tests/redis/configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat /vagrant/tests/redis/configs/ips$topology.txt) --cluster-yes
        sleep 30

        /vagrant/tests/redis/retrieve_container_info.sh $container_info
        sudo $main "sys_all_trace,container" $functions_file $binary_path $container_info "none" &

        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload
        /vagrant/tests/redis/run_ycsb.sh $workload_size sys_all_trace$topology:$run

        sudo kill -2 $ebpf_PID

        wait $ebpf_PID
        docker compose -f  /vagrant/tests/redis/configs/docker-compose$topology.yaml down
        sudo mv /tmp/history.txt results/history_sys_all_tracer_$topology:$run.txt
        sudo rm -r /redis/*
    done
    ############################################################################################################
    ############################################################################################################
    ############################################################################################################
    #RW Tracer Active
    sudo rm $file
    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        docker compose -f /vagrant/tests/redis/configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat /vagrant/tests/redis/configs/ips$topology.txt) --cluster-yes
        sleep 30

        /vagrant/tests/redis/retrieve_container_info.sh $container_info
        sudo $main "rw_trace,container" $functions_file $binary_path $container_info "none" &

        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload
        /vagrant/tests/redis/run_ycsb.sh $workload_size rw_trace$topology:$run

        sudo kill -2 $ebpf_PID

        wait $ebpf_PID
        docker compose -f  /vagrant/tests/redis/configs/docker-compose$topology.yaml down
        sudo mv /tmp/history.txt results/history_rw_tracer_$topology:$run.txt
        sudo rm -r /redis/*
    done

    ############################################################################################################
    ############################################################################################################
    ############################################################################################################

    #Prod Tracer Active
    sudo rm $file
    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        docker compose -f /vagrant/tests/redis/configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat /vagrant/tests/redis/configs/ips$topology.txt) --cluster-yes
        sleep 30

        /vagrant/tests/redis/retrieve_container_info.sh $container_info
        sudo $main "production_trace,container" $functions_file $binary_path $container_info "none" &

        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload
        /vagrant/tests/redis/run_ycsb.sh $workload_size prod_trace$topology:$run

        sudo kill -2 $ebpf_PID

        wait $ebpf_PID
        docker compose -f  /vagrant/tests/redis/configs/docker-compose$topology.yaml down
        sudo mv /tmp/history.txt results/history_prod_tracer_$topology:$run.txt
        sudo rm -r /redis/*
    done

done

reset
