#!/bin/bash
workload_size=1000000
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

for topology in 2 4 8 16
do
    for (( run=1; run<=$runs; run++ ))
        do
        #Normal run
        docker compose -f configs/docker-compose$topology.yaml up -d
        chmod +x configs/start$topology.sh
        sleep 15
        mongo0name=$(docker ps -aqf "name=mongo0")
        docker exec -d $mongo0name ./rs-init.sh

        #Wait for replicaset to start
        ready="No"
        while [ $ready == "No" ]
        do
            ready=$(python3 test.py)
            sleep 2
            echo $ready
        done

        echo Starting Workload
        /usr/bin/time -ao stats/times$date.txt -f "$run:v:$topology:%e" python3 workload.py $workload_size
        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /mongo/*
    done

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    faultsfile="faults.txt"
    echo $faultsfile

    for (( run=1; run<=$runs; run++ ))
    do
    docker compose -f configs/docker-compose$topology.yaml up -d
    sleep 30

    ./populatefaults.sh $faultsfile

    sudo $main $faultsfile &

    ebpf_PID=$!
    echo $ebpf_PID

    mongo0name=$(docker ps -aqf "name=mongo0")
    docker exec -d $mongo0name ./rs-init.sh

    #Wait for replicaset to start
    ready="No"
    while [ $ready == "No" ]
    do
        ready=$(python3 test.py)
        sleep 5
        echo $ready
    done

    echo Starting Workload

    /usr/bin/time -ao stats/times$date.txt -f "$run:e:$topology:%e" python3 workload.py $workload_size

    kill $ebpf_PID
    docker compose -f configs/docker-compose$topology.yaml down
    sudo rm -r /mongo/*
    done

done

cd stats
./generate_graphs.sh perfomance times$date.txt

