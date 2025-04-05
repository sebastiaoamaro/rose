#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
/vagrant/schedules/reproducedbugs/mongo/mongo_2.4.3/scripts/check_logs.sh > $folder$name$runnumber.txt

result=$(python3 /vagrant/schedules/reproducedbugs/mongo/mongo_2.4/scripts/detect_bug.py $folder$name$runnumber.txt)

echo $result
