#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat /vagrant/rw/Anduril/ground_truth/zookeeper-2247/output.log > $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "KeeperErrorCode = ConnectionLoss for /foo_q1")

echo $result
