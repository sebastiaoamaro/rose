#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
#/home/sebastiaoamaro/phd/roseredistests/checklogs.sh >> $folder$name$runnumber.txt
/vagrant/rw/redis_raft_bugs/checklogs.sh >> $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "Assertion")

echo $result
