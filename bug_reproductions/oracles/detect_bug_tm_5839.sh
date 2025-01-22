#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
#/home/sebastiaoamaro/phd/roseredistests/checklogs.sh >> $folder$name$runnumber.txt
mv /tmp/output.log $folder$name$runnumber.txt

result=$(cat $folder$name$runnumber.txt | grep "not permitted")

echo $result
