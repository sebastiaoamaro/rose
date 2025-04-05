#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
cat /vagrant/rw/Anduril/experiment/kafka-12508/output.log > $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "Did not receive all")

echo $result
