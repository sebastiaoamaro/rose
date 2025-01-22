#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat /home/sebastiaoamaro/phd/torefidevel/rw/Anduril/ground_truth/zookeeper-2247/output.log > $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "at org.apache.zookeeper.server.SyncRequestProcessor.flush(SyncRequestProcessor.java:178")

echo $result
