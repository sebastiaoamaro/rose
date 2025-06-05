#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
/vagrant/schedules/reproduced_bugs/redisraft/setup/checklogs.sh  > $folder$name$runnumber.txt
result=$(cat $folder$name$runnumber.txt | grep "assertion")
echo $result
