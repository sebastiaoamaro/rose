#!/bin/bash
workload_size=1000000
maindirectory=/home/sebasamaro/phd/torefidevel/examples/c/main
faultsfile=$maindirectory/"faults.txt"
#maindirectory=/vagrant/examples/c/main/main
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd /home/sebasamaro/phd/torefidevel/examples/c
cd /vagrant/examples/c/
rocksdir=/home/sebasamaro/phd/rocksdb/examples/c_simple_example
#rocksdir=/vagrant/rocksdb/examples/c_simple_example
make
cd $SCRIPT_DIR

for run in 
do  
    rm -r /tmp/*
    echo Starting Workload
    /usr/bin/time -ao stats/timesrocks$date.txt -f "$run:v:%e" $rocksdir $workload_size
done

############################################################################################################
############################################################################################################
############################################################################################################

for run in 1 2 3 4 5
do
    rm -r /tmp/*
    rm $faultsfile
    echo Starting Workload
    /usr/bin/time -ao stats/timesrocks$date.txt -f "$run:e:%e" $rocksdir $workload_size &
    rockspid=$!

    echo $rockspid";" >> $faultsfile
    $maindirectory/main -f 1 -d 0 -i $faultsfile &
    ebpf_PID=$!

    while kill -0 $rockspid 2> /dev/null; do sleep 1; done;

    echo $ebpf_PID
    kill $ebpf_PID
    
    sleep 5
done

cd stats
./generate_graphs.sh perfomance timesrocks$date.txt

