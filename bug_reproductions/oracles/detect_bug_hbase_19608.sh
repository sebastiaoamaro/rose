#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat /vagrant/rw/Anduril/experiment/hbase-19608/output.log > $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "OK (1 test)")

echo $result
