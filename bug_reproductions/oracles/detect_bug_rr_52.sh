#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat "/vagrant/schedules/reproducedbugs/redisraft/lxc/redis/store/current/results.edn"  > $folder$name$runnumber.txt
result=$(cat $folder$name$runnumber.txt | grep "order")

echo $result
