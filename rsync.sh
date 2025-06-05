#!/bin/bash
rsync -rav --exclude .git/ --exclude schedules/reproduced_bugs/redpanda/setup/repos/ --exclude .vagrant/ --exclude rw/Anduril/ --exclude rose/kernelmodule/dwarves --exclude schedules/generatedschedules/ --exclude tracer/target/ -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@$1:./torefidevel/

if [ "$#" -eq 2 ]; then
    command="cd torefidevel && vagrant rsync $2"
    ssh sebasamaro@$1 $command
fi
