#!/bin/bash


##############
#NEEDS UPDATE#
##############

workload_size=10000000
#maindirectory=/home/sebastiaoamaro/phd/torefidevel/rosetracer
maindirectory=/vagrant/rosetracer/
main=/vagrant/rosetracer/target/release/rosetracer
#main=/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $maindirectory
#bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
cd $SCRIPT_DIR

chmod +x configs/setup.sh
chmod +x runycsb.sh
sudo rm -r /redis/*

for topology in 3 6 12
do
    #sudo /vagrant/tests/redis/configs/setup.sh $topology
    #sudo /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/setup.sh $topology

    # docker compose -f configs/docker-compose$topology.yaml up -d
    # sleep 30

    # redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes

    # sleep 30

    # echo Starting Workload
    # dstat --output stats/statsvanilla$topology.txt &
    # dstatpid=$!
    # ./ycsb.sh $workload_size topology$topology:$run
    # kill $dstatpid
    # docker compose -f configs/docker-compose$topology.yaml down
    # sudo rm -r /redis/*

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    faultsfile="faults.txt"

    sudo /vagrant/tests/redis/configs/setup.sh $topology
    #sudo /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/setup.sh $topology
    docker compose -f configs/docker-compose$topology.yaml up -d

    sleep 30

    redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes

    sleep 30
    ./populatefaults.sh $faultsfile

    sudo $main $faultsfile $topology &
    ebpf_PID=$!
    echo $ebpf_PID

    echo Starting Workload
    dstat --output stats/statseBPF$topology.txt &
    dstatpid=$!
    ./ycsb.sh $workload_size topology$topology:$run
    kill $dstatpid
    kill $ebpf_PID
    docker compose -f configs/docker-compose$topology.yaml down
    sudo rm -r /redis/*
done

cd stats
./generate_graphs.sh usage

#cleanup
rm stats*.txt
rm stats*.csv