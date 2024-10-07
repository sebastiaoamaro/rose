#!/bin/bash

main=target/debug/uprobetest
gcc -O0 test_write.c -o src/write

cargo build
./src/write &
traced_pid=$!
#echo "Traced pid is $traced_pid"
sudo $main $traced_pid

kill $traced_pid