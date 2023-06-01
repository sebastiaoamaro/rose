#!/bin/bash
rm stats/times.txt
workload_size=1_00_000
#maindirectory=/home/sebasamaro/phd/torefidevel/examples/c/main/main
maindirectory=/vagrant/examples/c/main/main
currentdevices=$(ls -A /sys/class/net | wc -l)
timestamp=$(date +%s)

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
    for run in 1 2 3 4 5
    do
            /usr/bin/time -ao stats/times$timestamp.txt -f "$run:v:$topology:%e" python3 workload.py $workload_size
    done
    docker compose -f configs/docker-compose$topology.yaml down

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    docker compose -f configs/docker-compose$topology.yaml up -d

    let devices=$currentdevices+$topology
    $maindirectory -f 0 -d $devices &
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
    for run in 1 2 3 4 5
    do
        /usr/bin/time -ao stats/times$timestamp.txt -f "$run:e:$topology:%e" python3 workload.py $workload_size
    done
    kill $ebpf_PID
    docker compose -f configs/docker-compose$topology.yaml down
done

cd stats
./generate_graphs.sh perfomance

#cleanup
rm times.data