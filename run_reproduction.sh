#!/bin/bash

#Build tracer
cd tracer
cargo build --release
cd ..

#Runs a schedule
if [ "$#" -eq 1 ]; then
    if [ -n "$1" ]; then
        # If checks pass, proceed
        echo "Arguments provided: $1"
        schedule=$1
        sudo rm /tmp/containerpid_read
        sudo rm /tmp/containerpid_write
        sudo rm /tmp/history.txt
        sudo insmod executor/kernelmodule/rose.ko
        python3 parser.py $schedule
        mv fault_schedule.c executor/c/
        cd executor/c/
        make -j$(nproc)
        sudo -E ./main/main
    fi
fi

if [ "$#" -gt 4 ]; then
    mode=$1
    #Runs all schedules in folder
    if [ "$1" = "folder" ]; then
        dir=$2
        output_folder=$3
        oracle=$4
        cleanup=$5
        echo "Arguments provided: $1,$2,$3,$4"
        for file in "$dir"/*; do
            if [ -f "$file" ]; then
                schedule=$file
                sudo rm /tmp/containerpid_read
                sudo rm /tmp/containerpid_write
                sudo rm /tmp/history.txt
                sudo insmod executor/kernelmodule/rose.ko
                python3 parser.py $schedule
                mv fault_schedule.c executor/c/
                cd executor/c/
                make -j$(nproc)
                sudo -E ./main/main
                cd ../../
                filename=$(basename $file)
                sudo mv /tmp/history.txt $output_folder/$filename.txt
                sh $oracle $filename $output_folder
                sh $cleanup
            fi
        done
    fi
    #Runs schedule a set amount of times
    if [ "$1" = "runs" ]; then
        runs=$2
        schedule=$3
        output_folder=$4
        oracle=$5
        cleanup=$6
        echo "Arguments provided: $1,$2,$3,$4,$5"
        for ((i = 1; i <= $runs; i++)); do
            sudo rm /tmp/containerpid_read
            sudo rm /tmp/containerpid_write
            sudo rm /tmp/history.txt
            sudo insmod executor/kernelmodule/rose.ko
            python3 parser.py $schedule
            mv faultschedule.c executor/c/
            cd executor/c/
            make -j$(nproc)
            sudo -E ./main/main
            cd ../../
            sudo mv /tmp/history.txt $output_folder/$i.txt
            sh $oracle $i $output_folder
            sh $cleanup
        done
    fi
fi
