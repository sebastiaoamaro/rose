#!/bin/bash
workload_size=100000000
#workload_size=100000
maindirectory=/home/sebastiaoamaro/phd/torefidevel/examples/c/main
faultsfile=$maindirectory/"faults.txt"
#maindirectory=/vagrant/examples/c/main/
date=$(date +"%H:%M")
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd /home/sebastiaoamaro/phd/torefidevel/examples/c/
make

#cd /vagrant/examples/c/
#rocksexecutable=/home/sebastiaoamaro/phd/rocksdb/examples/c_simple_example
rockscfile=/home/sebastiaoamaro/phd/rocksdb/examples/compact_files_example.cc
rocksexecutable=/home/sebastiaoamaro/phd/rocksdb/examples/compact_files_example
rocksdir=/home/sebastiaoamaro/phd/rocksdb/examples

mv $rockscfile /home/sebastiaoamaro/phd/rocksdb/examples/

cd $rocksdir
make
#rocksexecutable=/vagrant/rocksdb/examples/c_simple_example

cd $SCRIPT_DIR

rm -r /tmp/*
for run in    
do  
    echo Starting Workload
    /usr/bin/time -ao stats/timesrocks$date.txt -f "$run:v:%e" $rocksexecutable $workload_size
done

############################################################################################################
############################################################################################################
############################################################################################################

for run in 1
do
    rm $faultsfile
    echo Starting Workload
    /usr/bin/time -ao stats/timesrocks$date.txt -f "$run:e:%e" $rocksexecutable $workload_size &

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

# cd stats
# ./generate_graphs.sh perfomance timesrocks$date.txt

