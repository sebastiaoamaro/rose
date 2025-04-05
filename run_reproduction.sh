#!/bin/bash

#Build tracer
cd rosetracer
cargo build --release
cd ..

#Runs a schedule
if [ "$#" -eq 1 ]; then
    if [ -n "$1" ]; then
        # If checks pass, proceed
        echo "Arguments provided: $1"
        schedule=$1
        sudo rm /tmp/containerpid
        sudo rm /tmp/history.txt
        sudo insmod rose/kernelmodule/rose.ko
        python3 schedule_parser.py $schedule
        mv faultschedule.c rose/c/
        cd rose/c/
        make -j$(nproc)
        sudo -E ./main/main
    fi
fi

#Runs all schedules in folder $1, moves histories and logs to folder $2, $3 is the script which check for bugs and moves logs to folder $2
if [ "$#" -eq 3 ]; then
    if [ -d "$1" ]; then
        echo "Arguments provided: $1,$2,$3"
        dir="$1"
        for file in "$dir"/*; do
            if [ -f "$file" ]; then
                schedule=$file
                sudo rm /tmp/containerpid
                sudo rm /tmp/history.txt
                sudo insmod rose/kernelmodule/rose.ko
                python3 schedule_parser.py $schedule
                mv faultschedule.c rose/c/
                cd rose/c/
                make -j$(nproc)
                sudo -E ./main/main
                cd ../../
                filename=$(basename $file)
                sudo mv /tmp/history.txt $2/$filename.txt
                sh $3 $filename $2
            fi
        done
    fi
fi
