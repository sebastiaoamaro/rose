#!/bin/bash
rm stats/times.txt
rm stats/stats*.txt
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
        sleep 5
        echo $ready
    done

    echo Starting Workload
    dstat --output stats/statsvanilla$topology.txt &
    dstatpid=$!
    /usr/bin/time -ao stats/times.txt -f "Workload vanilla Replicas:$topology took %e" python3 workload.py
    kill $dstatpid
    docker compose -f configs/docker-compose$topology.yaml down

############################################################################################################
############################################################################################################
############################################################################################################

    #Tracing active
    docker compose -f configs/docker-compose$topology.yaml up -d

    /home/sebasamaro/phd/libbpf-bootstrap/examples/c/main/main &
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
    /usr/bin/time -ao stats/times.txt -f "Workload with eBPF Replicas:$topology took %e" python3 workload.py
    kill $dstatpid
    docker compose -f configs/docker-compose$topology.yaml down
    kill $ebpf_PID
done


cd stats
./generate_graphs.sh