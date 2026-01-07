#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat /vagrant/rw/Anduril/experiment/hdfs-4233/cluster/logs-1/hadoop-root-namenode-vagrant.log > $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "Unable to start log segment 7")

echo $result
