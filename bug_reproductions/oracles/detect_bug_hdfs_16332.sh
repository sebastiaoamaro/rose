#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat /home/sebastiaoamaro/phd/torefidevel/rw/Anduril/experiment/hdfs-16332/output.log > $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "DIGEST-MD5: IO error acquiring password")

echo $result
