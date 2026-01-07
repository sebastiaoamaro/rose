#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat /vagrant/rw/Anduril/experiment/hdfs-15032/output.log > $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "org.apache.hadoop.hdfs.server.namenode.ha.ObserverReadProxyProvider.getHAServiceState(ObserverReadProxyProvider.java:276)")

echo $result
