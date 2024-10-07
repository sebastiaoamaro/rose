#!/bin/bash
#workload_size=500000
workload_size=2500000
runs=5
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
sudo rm /tmp/read_average*

ulimit -n 4096
#rm results/*
#for topology in 3 6 12
for topology in 6
do
    # for (( run=1; run<=$runs; run++ ))
    # do
    #     sudo /vagrant/tests/redis/configs/setup.sh $topology
    #     #sudo /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/setup.sh $topology
    #     #Normal run
    #     docker compose -f configs/docker-compose$topology.yaml up -d
    #     sleep 30
    #     redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes
    #     sleep 30

    #     echo Starting Workload
    #     #/usr/bin/time -ao stats/times$date.txt -f "$run:v:$topology:%e" ./ycsb.sh $workload_size topology$topology:$run
    #     ./ycsb.sh $workload_size topology$topology:$run
    #     docker compose -f configs/docker-compose$topology.yaml down
    #     sudo rm -r /redis/*
    # done

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    pids="pids.txt"
    container_names="container_names.txt"
    functions_file="functions.txt"
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

        ./retrievecontainerinfo.sh $pids $container_names
        sudo $main $pids "tracer" $functions_file $container_names $binary_path &
        ebpf_PID=$!
        while [ ! -s "$file" ]; do
            #echo "File is empty or does not exist. Waiting..."
            sleep 1  # Wait for 5 seconds before checking again
        done

        echo Starting Workload

        ./runycsb.sh $workload_size tracerontopology$topology:$run

        echo Sent -2 to $ebpf_PID

        sudo kill -2 $ebpf_PID
        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /redis/*
    done

done

reset
#cd stats
#./generate_graphs.sh perfomance times$date.txt
