#!/bin/bash
workload_size=20000000
runs=10
#maindirectory=/home/sebastiaoamaro/phd/torefidevel/examples/c/main
faultsfile=$maindirectory/"faults.txt"
maindirectory=/vagrant/examples/c/main/
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
#cd /home/sebastiaoamaro/phd/torefidevel/examples/c/
cd /vagrant/examples/c/
make

# rockscfile=/home/sebastiaoamaro/phd/torefidevel/tests/rocksdb/compact_files_example.cc
# rocksexecutable=/home/sebastiaoamaro/phd/rocksdb/examples/compact_files_example
# rocksdir=/home/sebastiaoamaro/phd/rocksdb/examples

rockscfile=/vagrant/tests/rocksdb/c_simple_example.c
rocksexecutable=/vagrant/rocksdb/examples/c_simple_example
rocksdir=/vagrant/rocksdb/examples/

#cp $rockscfile /home/sebastiaoamaro/phd/rocksdb/examples/compact_files_example.cc
cp $rockscfile /vagrant/rocksdb/examples/c_simple_example.c

cd $rocksdir
make

cd $SCRIPT_DIR

rm -r /tmp/*
for (( run=1; run<=$runs; run++ ))
do  
    #rm -r /tmp/*
    echo Starting Workload
    /usr/bin/time -ao stats/timesrocks$date.txt -f "$run:v:%e" $rocksexecutable $workload_size
done

############################################################################################################
############################################################################################################
############################################################################################################

rm -r /tmp/*
for (( run=1; run<=$runs; run++ ))
do
    #rm -r /tmp/*
    rm $faultsfile
    echo Starting Workload
    /usr/bin/time -ao stats/timesrocks$date.txt -f "$run:u:%e" $rocksexecutable $workload_size &

    rockspid=$(pgrep -f $rocksdir | awk 'NR==2{print $1}')
    echo "PID IN BASH IS " $pid

    echo $rockspid";" >> $faultsfile
    $maindirectory/main -f 1 -d 0 -u -t -i $faultsfile &
    ebpf_PID=$!

    while kill -0 $rockspid 2> /dev/null; do sleep 1; done;

    echo $ebpf_PID
    kill $ebpf_PID
    sleep 5
done

############################################################################################################
############################################################################################################
############################################################################################################

rm -r /tmp/*
for (( run=1; run<=$runs; run++ ))
do
    #rm -r /tmp/*
    rm $faultsfile
    echo Starting Workload
    /usr/bin/time -ao stats/timesrocks$date.txt -f "$run:uf:%e" $rocksexecutable $workload_size &

    rockspid=$(pgrep -f $rocksdir | awk 'NR==2{print $1}')
    echo "PID IN BASH IS " $pid

    echo $rockspid";" >> $faultsfile
    $maindirectory/main -f 1 -d 0 -u -i $faultsfile &
    ebpf_PID=$!

    while kill -0 $rockspid 2> /dev/null; do sleep 1; done;

    echo $ebpf_PID
    kill $ebpf_PID
    sleep 5
done

############################################################################################################
############################################################################################################
############################################################################################################

rm -r /tmp/*
for (( run=1; run<=$runs; run++ ))
do
    #rm -r /tmp/*
    rm $faultsfile
    echo Starting Workload
    /usr/bin/time -ao stats/timesrocks$date.txt -f "$run:a:%e" $rocksexecutable $workload_size &

    rockspid=$(pgrep -f $rocksdir | awk 'NR==2{print $1}')
    echo "PID IN BASH IS " $pid

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

