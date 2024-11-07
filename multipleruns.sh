#!/bin/bash

#This should be arguments in the future, however they are super long thus hard to fit in the shell
runs=50
schedule="/home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/bug_42_104.yaml"
condition_script="/home/sebastiaoamaro/phd/roseredistests/detectbug.sh"
cleanup_script="/home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/scripts/cleanup.sh"
result_folder="/home/sebastiaoamaro/phd/torefidevel/tests/bugdetection/redisraft/currentrun"
tracer_history_location="/tmp/history.txt"

sudo rm /tmp/containerpid
sudo rm $result_folder/*
for (( i=1; i<=$runs; i++ ))
do
    ./runschedule.sh $schedule
    result=$($condition_script $i "Assertion" $result_folder)
    
    if [ -n "$result" ]; then
        echo "Buggy run: $i \n" >> $result_folder/buggyruns.txt
    fi
    
    $cleanup_script

    sudo mv $tracer_history_location $result_folder/history$i.txt

done