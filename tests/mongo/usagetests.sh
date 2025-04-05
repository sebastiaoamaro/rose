#!/bin/bash

workload_size=500_000
#maindirectory=/home/sebasamaro/phd/torefidevel/examples/c/main/main
maindirectory=/vagrant/examples/c/main/main

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
#cd /home/sebasamaro/phd/torefidevel/examples/c
cd /vagrant/examples/c/
make
cd $SCRIPT_DIR

for topology in 2 4 8 16
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
    dstat --output stats/statsvanilla$topology.txt &
    dstatpid=$!
    /usr/bin/time -ao stats/times.txt -f "Workload vanilla Replicas:$topology took %e" python3 workload.py $workload_size
    kill $dstatpid
    docker compose -f configs/docker-compose$topology.yaml down

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    docker compose -f configs/docker-compose$topology.yaml up -d

    currentdevices=$(ls -A /sys/class/net | wc -l)
    
    $maindirectory -f 1 -d $currentdevices &
    ebpf_PID=$!
    echo $ebpf_PID

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
    dstat --output stats/statseBPF$topology.txt &
    dstatpid=$!
    /usr/bin/time -ao stats/times.txt -f "Workload with eBPF Replicas:$topology took %e" python3 workload.py $workload_size
    kill $dstatpid
    kill $ebpf_PID
    docker compose -f configs/docker-compose$topology.yaml down
done

cd stats
./generate_graphs.sh usage

#cleanup
rm stats*.txt
rm stats*.csv