#!/bin/bash

#This should be arguments in the future, however they are super long thus hard to fit in the shell
runs=15
schedule="/home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/bug_42_104.yaml"
#schedule="/home/sebastiaoamaro/phd/torefidevel/rose/new_schedule.yaml"
condition_script="/home/sebastiaoamaro/phd/roseredistests/detectbug.sh"
cleanup_script="/home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/scripts/cleanup.sh"
result_folder="/home/sebastiaoamaro/phd/torefidevel/tests/bugdetection/redisraft/currentrun"
tracer_history_location="/tmp/history.txt"

sudo rm /tmp/containerpid
sudo rm $result_folder/*

#Compile schedule once
sudo rm /tmp/containerpid
python3 rose/faultscheduleparser.py $schedule
mv faultschedule.c rose/c/
cd rose/c/
make;
cp ./main/main currentrosetest

for (( i=1; i<=$runs; i++ ))
do
    #./runschedule.sh $schedule
    sudo ./currentrosetest -v
    result=$($condition_script $i "Assertion" $result_folder)
    
    if [ -n "$result" ]; then
        echo "Buggy run: $i \n" >> $result_folder/buggyruns.txt
    fi
    
    $cleanup_script

    sudo mv $tracer_history_location $result_folder/history$i.txt

done