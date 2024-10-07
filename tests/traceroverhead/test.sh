#!/bin/bash

test_type=$1
string="local"

if [ "$test_type" = "$string" ]; then
    echo "The string matches."
    maindirectory=/home/sebastiaoamaro/phd/torefidevel/rosetracer/
    main=/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer
else
    maindirectory=/vagrant/rosetracer/
    main=/vagrant/rosetracer/target/release/rosetracer
fi


SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pids="pids.txt"
strings=("vanilla" "intercept" "intercept_and_count" "count_syscalls" "save_info" "save_io")
#strings=("vanilla" "uprobes")
#strings=("uprobes")
runs=30
output_file="output.log"
functions_file="functions.txt"
results="results.txt"

#########################
#########################
rm $pids
rm $output_file
rm $results

echo "Building tracer"
cd $maindirectory
cargo build --release
cd $SCRIPT_DIR

gcc -O0 test_write.c -o write

for tracing_type in "${strings[@]}"; do
    for (( run=1; run<=$runs; run++ ))
        do
        ./write $tracing_type >> $output_file 2>&1 &
        traced_pid=$!
        #echo "Traced pid is $traced_pid"

        echo $traced_pid >> $pids
        sleep 1
        sudo $main $pids $tracing_type $functions_file&
        ebpf_pid=$!

        sudo kill -SIGUSR1 $traced_pid
        #echo "Sent signal to $traced_pid"

        wait $traced_pid
        kill -9 $ebpf_pid
        rm $pids
        rm teste.txt
        done
done

process_results.sh $output_file $results $runs