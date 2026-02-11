#!/bin/bash
#workload_size=25000000
workload_size=250000
runs=2
maindirectory=/vagrant/tracer
main=/vagrant/tracer/target/release/tracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
HOME_DIR=/vagrant/artifact_evaluation/tracing_overhead/throughput
RESULT_DIR=/vagrant/artifact_evaluation/tracing_overhead/throughput/results

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
        sudo $HOME_DIR/configs/setup.sh $topology
        #Normal run
        sudo docker compose -f  $HOME_DIR/configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat $HOME_DIR/configs/ips$topology.txt) --cluster-yes
        sleep 30

        echo Starting Workload
        $HOME_DIR/run_ycsb.sh $workload_size $RESULT_DIR/vanilla$topology:$run
        docker compose -f  $HOME_DIR/configs/docker-compose$topology.yaml down
        sudo rm -r /redis/*
    done

############################################################################################################
############################################################################################################
############################################################################################################

    #SysAll Tracer Active
    container_info="/vagrant/artifact_evaluation/tracing_overhead/throughput/container_and_pid.txt"
    functions_file="/vagrant/profiler/redis/functions.txt"
    file="check.txt"
    binary_path="/usr/local/bin/redis-server"

    sudo rm $file
    for (( run=1; run<=$runs; run++ ))
    do
        sudo $HOME_DIR/configs/setup.sh $topology
        sudo docker compose -f $HOME_DIR/configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat $HOME_DIR/configs/ips$topology.txt) --cluster-yes
        sleep 30

        $HOME_DIR/retrieve_container_info.sh $container_info
        sudo $main "sys_all_trace,container" $functions_file $binary_path $container_info "none" &

        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload
        $HOME_DIR/run_ycsb.sh $workload_size $RESULT_DIR/full_trace:$run

        sudo kill -2 $ebpf_PID

        wait $ebpf_PID
        sudo docker compose -f  $HOME_DIR/configs/docker-compose$topology.yaml down
        sudo mv /tmp/history.txt results/history_full_trace:$run.txt
        sudo rm -r /redis/*
    done
    ############################################################################################################
    ############################################################################################################
    ############################################################################################################
    #RW Tracer Active
    sudo rm $file
    for (( run=1; run<=$runs; run++ ))
    do
        sudo $HOME_DIR/configs/setup.sh $topology
        sudo docker compose -f $HOME_DIR/configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat $HOME_DIR/configs/ips$topology.txt) --cluster-yes
        sleep 30

        $HOME_DIR/retrieve_container_info.sh $container_info
        sudo $main "rw_trace,container" $functions_file $binary_path $container_info "none" &

        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload
        $HOME_DIR/run_ycsb.sh $workload_size $RESULT_DIR/io_trace:$run

        sudo kill -2 $ebpf_PID

        wait $ebpf_PID
        sudo docker compose -f  $HOME_DIR/configs/docker-compose$topology.yaml down
        sudo mv /tmp/history.txt results/history_io_trace:$run.txt
        sudo rm -r /redis/*
    done

    ############################################################################################################
    ############################################################################################################
    ############################################################################################################

    #Prod Tracer Active
    sudo rm $file
    for (( run=1; run<=$runs; run++ ))
    do
        sudo $HOME_DIR/configs/setup.sh $topology
        sudo docker compose -f $HOME_DIR/configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat $HOME_DIR/configs/ips$topology.txt) --cluster-yes
        sleep 30

        $HOME_DIR/retrieve_container_info.sh $container_info
        sudo $main "production_trace,container" $functions_file $binary_path $container_info "none" &

        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload
        $HOME_DIR/run_ycsb.sh $workload_size $RESULT_DIR/production_trace:$run

        sudo kill -2 $ebpf_PID

        wait $ebpf_PID
        sudo docker compose -f  $HOME_DIR/configs/docker-compose$topology.yaml down
        sudo mv /tmp/history.txt results/history_production_trace:$run.txt
        sudo rm -r /redis/*
    done

done

cd /vagrant/artifact_evaluation/tracing_overhead/throughput/
python3 calculate_overhead.py results/ > /shared/throughtput_overhead.txt
