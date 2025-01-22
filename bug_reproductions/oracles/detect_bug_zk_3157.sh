#!/bin/bash
runnumber=$1
keyword=$2
folder=$3
#Save logs
cat /home/sebastiaoamaro/phd/rw/Anduril/ground_truth/zookeeper-3157/output.log >> $folder/$runnumber.txt

result=$(cat $folder/$runnumber.txt | grep "FAILURES")

echo $result
