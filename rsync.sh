#!/bin/bash
rsync -rav --exclude schedules/reproducedbugs/redpanda/setup/repos/ --exclude .vagrant/ --exclude rw/Anduril/ --exclude rose/kernelmodule/dwarves --exclude schedules/generatedschedules/ --exclude rosetracer/target/ -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@$1:./torefidevel/

if [ "$#" -eq 2 ]; then
    command="cd torefidevel && vagrant rsync $2"
    ssh sebasamaro@$1 $command
fi
