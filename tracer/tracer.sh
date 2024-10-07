#!/bin/bash
workload_size=2500000
runs=1
maindirectory=/home/sebastiaoamaro/phd/torefidevel/rosetracer/
main=/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer
# maindirectory=/vagrant/rosetracer/
# main=/vagrant/rosetracer/target/release/rosetracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $maindirectory
#bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
cd $SCRIPT_DIR

sudo rm -r /redis/*
sudo rm /tmp/read_average*

ulimit -n 4096
#rm results/*
#for topology in 3 6 12

    #Tracing active
    pids="pids.txt"
    container_names="container_names.txt"
    functions_file="functions.txt"
    file="check.txt"
    probe_stats="probe_stats.txt"
    binary_path="/redisraft.so"
    collect_process_info_pipe="/tmp/pidscontainers"

    setup="/home/sebastiaoamaro/phd/torefidevel/tracer/redisraft/setup.sh"
    workload="/home/sebastiaoamaro/phd/torefidevel/tracer/redisraft/runworkload.sh"
    cleanup="/home/sebastiaoamaro/phd/torefidevel/tracer/redisraft/cleanup.sh"

    # setup="/home/sebastiaoamaro/phd/torefidevel/tracer/redis/setup.sh"
    # workload="/home/sebastiaoamaro/phd/torefidevel/tracer/redis/runworkload.sh"
    # cleanup="/home/sebastiaoamaro/phd/torefidevel/tracer/redis/cleanup.sh"


for (( run=1; run<=$runs; run++ ))
do
    sudo rm $file
    sudo rm $probe_stats
    touch $probe_stats

    #sudo /vagrant/tests/redis/configs/setup.sh $topology

    $setup
    ./retrievecontainerinfo.sh $pids $container_names
    sudo $main $pids "tracer" $functions_file $container_names $binary_path $collect_process_info_pipe > traceroutput$run.txt 2>&1 &
    ebpf_PID=$!
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

    sleep 3
    python3 remove_probes.py $probe_stats $elapsed_time $functions_file > python_output$run.txt
done


reset
#cd stats
#./generate_graphs.sh perfomance times$date.txt
