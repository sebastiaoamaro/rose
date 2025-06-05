#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat "/vagrant/schedules/reproduced_bugs/redpanda/lxc/redpanda_jepsen/store/current/results.edn" > $folder$name$runnumber.txt
result=$(cat $folder$name$runnumber.txt  | grep "poll-skip")
echo $result
