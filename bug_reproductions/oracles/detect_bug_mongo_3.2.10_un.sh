#!/bin/bash
runnumber=$1
folder=$2
name="logs_run:"
#Save logs
/vagrant/schedules/reproducedbugs/mongo/mongo_3.2.10/scripts/check_logs.sh > $folder$name$runnumber.txt

result=$(/vagrant/schedules/reproducedbugs/mongo/mongo_3.2.10/scripts/detect_bug.sh $folder$name$runnumber.txt)

echo $result
