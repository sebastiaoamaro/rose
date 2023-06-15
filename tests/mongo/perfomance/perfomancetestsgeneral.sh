#!/bin/bash
workload_size=1_000
maindirectory=/home/sebasamaro/phd/torefidevel/examples/c/main/main
#maindirectory=/vagrant/examples/c/main/main
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd /home/sebasamaro/phd/torefidevel/examples/c
#cd /vagrant/examples/c/
make
cd $SCRIPT_DIR

for topology in 2
do
    # for run in 1 2 3 4 5
    #     do
    #     #Normal run
    #     docker compose -f configs/docker-compose$topology.yaml up -d
    #     chmod +x configs/start$topology.sh
    #     sleep 15
    #     mongo0name=$(docker ps -aqf "name=mongo0")
    #     docker exec -d $mongo0name ./rs-init.sh

    #     #Wait for replicaset to start
    #     ready="No"
    #     while [ $ready == "No" ]
    #     do
    #         ready=$(python3 test.py)
    #         sleep 2
    #         echo $ready
    #     done

    #     echo Starting Workload
    #             /usr/bin/time -ao stats/times$date.txt -f "$run:v:$topology:%e" python3 workload.py $workload_size
    #     docker compose -f configs/docker-compose$topology.yaml down
    #     rm -r /mongo/*
    # done

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    currentdevices=$(ls -A /sys/class/net | wc -l)
    $maindirectory -f $topology -d $currentdevices &
    ebpf_PID=$!
    echo $ebpf_PID

    for run in 1 2 3 4 5
    do
    docker compose -f configs/docker-compose$topology.yaml up -d
    sleep 15
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
    docker compose -f configs/docker-compose$topology.yaml down
    rm -r /mongo/*
    done

    kill $ebpf_PID
done

cd stats
./generate_graphs.sh perfomance times$date.txt

