#!/bin/bash
workload_size=10000
runs=2
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

sudo rm /tmp/read_average*
for topology in 6 12
do
    for (( run=10; run<=$runs; run++ ))
        do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        #Normal run
        docker compose -f configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-replicas 1 --cluster-yes
        sleep 30

        echo Starting Workload
        /usr/bin/time -ao stats/times$date.txt -f "$run:v:$topology:%e" python3 workload.py $workload_size
        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /redis/*
    done

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    faultsfile="faults.txt"
    echo $faultsfile

    for (( run=1; run<=$runs; run++ ))
    do
        sudo /vagrant/tests/redis/configs/setup.sh $topology
        docker compose -f configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-replicas 1 --cluster-yes
        sleep 30

        ./populatefaults.sh $faultsfile

        sudo $main $faultsfile $topology &

        ebpf_PID=$!
        echo $ebpf_PID

        echo Starting Workload

        /usr/bin/time -ao stats/times$date.txt -f "$run:e:$topology:%e" python3 workload.py $workload_size

        kill -2 $ebpf_PID
        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /redis/*
    done

done

#cd stats
#./generate_graphs.sh perfomance times$date.txt

