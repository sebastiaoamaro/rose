#!/bin/bash
runnumber=$1
keyword=$2
folder=$3
#Save logs
cat /home/sebastiaoamaro/phd/torefidevel/rw/Anduril/experiment/hdfs-12070/output.log >> $folder/$runnumber.txt

result=$(cat $folder/$runnumber.txt | grep "FAILURES")

echo $result
