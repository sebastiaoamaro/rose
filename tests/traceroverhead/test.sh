#!/bin/bash
maindirectory=/home/sebastiaoamaro/phd/torefidevel/rosetracer/
main=/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pids="pids.txt"
strings=("intercept" "intercept_and_count" "count_syscalls" "save_info" "save_io")
runs=3
output_file="output.log"
#########################
#########################
rm $pids
rm $output_file
echo "Building tracer"
cd $maindirectory
cargo build --release
cd $SCRIPT_DIR

gcc test_write.c -o write
#########################
#########################

for (( run=1; run<=$runs; run++ ))
    do
    ./write "vanilla" >> output.log 2>&1 &
    traced_pid=$!
    sudo kill -SIGUSR1 $traced_pid
    echo "Sent signal to $traced_pid"
    wait $traced_pid
done
 #########################
 #########################

for tracing_type in "${strings[@]}"; do
    for (( run=1; run<=$runs; run++ ))
        do
        ./write $tracing_type >> $output_file 2>&1 &
        traced_pid=$!
        echo "Traced pid is $traced_pid"

        echo $traced_pid >> $pids

        sudo $main $pids $tracing_type &

        sudo kill -SIGUSR1 $traced_pid
        echo "Sent singal to $traced_pid"

        wait $traced_pid
        done
done
