#!/bin/bash
workload_size=100000000
runs=3
maindirectory=/home/sebastiaoamaro/phd/torefidevel/rosetracer/
main=/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer
#maindirectory=/vagrant/rosetracer/
#main=/vagrant/rosetracer/target/release/rosetracer
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $maindirectory
#bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
cd $SCRIPT_DIR

chmod +x configs/setup.sh
chmod +x ycsb.sh

sudo rm -r /redis/*
sudo rm /tmp/read_average*

#rm results/*
for topology in 3 6 12
do
    #for (( run=1; run<=$runs; run++ ))
    #do
        # sudo /vagrant/tests/redis/configs/setup.sh $topology
        # #Normal run
        # docker compose -f configs/docker-compose$topology.yaml up -d
        # sleep 30
        # redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes
        # sleep 30

        # echo Starting Workload
        # #/usr/bin/time -ao stats/times$date.txt -f "$run:v:$topology:%e" ./ycsb.sh $workload_size topology$topology:$run
        # ./ycsb.sh $workload_size topology$topology:$run
        # docker compose -f configs/docker-compose$topology.yaml down
        # sudo rm -r /redis/*
    #done

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    pids="pids.txt"
    container_names="container_names.txt"
    functions_file="functions_no_cold.txt"
    file="check.txt"
    functions_probed="functions_probed.txt"

    sudo rm $file
    sudo rm $functions_probed

    for (( run=1; run<=$runs; run++ ))
    do
        #sudo /vagrant/tests/redis/configs/setup.sh $topology
        sudo /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/setup.sh $topology
        docker compose -f configs/docker-compose$topology.yaml up -d
        sleep 30
        redis-cli --cluster create $(cat configs/ips$topology.txt) --cluster-yes
        sleep 30

        ./populatefaults.sh $pids $container_names
        sudo $main "save_io" $pids &
#        while [ ! -s "$file" ]; do
#            #echo "File is empty or does not exist. Waiting..."
#            sleep 5  # Wait for 5 seconds before checking again
#        done
        ebpf_PID=$!

        echo Starting Workload

        #sleep 100
        #/usr/bin/time -ao stats/times$date.txt -f "$run:e:$topology:%e" python3 workload.py $workload_size
        ./ycsb.sh $workload_size tracerontopology$topology:$run

        kill -2 $ebpf_PID
        docker compose -f configs/docker-compose$topology.yaml down
        sudo rm -r /redis/*
    done

done

#cd stats
#./generate_graphs.sh perfomance times$date.txt
