#!/bin/bash
TARGET_DIR=$1

condition_script="/home/sebastiaoamaro/phd/roseredistests/detectbug.sh"
cleanup_script="/home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/cleanup.sh"
result_folder="/home/sebastiaoamaro/phd/torefidevel/tests/bugdetection/redisraft/currentrun"

# Check if the directory exists
if [ ! -d "$TARGET_DIR" ]; then
    echo "Directory $TARGET_DIR does not exist."
    exit 1
fi

# Iterate over each file in the directory
for schedule in "$TARGET_DIR"/*; do
  # Check if it's a file (not a directory)
    if [ -f "$schedule" ]; then
        ./runschedule.sh $schedule
        
        schedule_name=$(basename "$schedule")
        result=$($condition_script $schedule_name "Assertion" $result_folder)

        if [ -n "$result" ]; then
            echo "Buggy run: $schedule_name \n" >> $result_folder/buggyruns.txt
        fi

        $cleanup_script
    fi
done