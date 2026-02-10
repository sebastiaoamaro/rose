#!/bin/bash
rsync -rav --exclude schedules/reproduced_bugs/redpanda/setup/ --exclude .vagrant/ --exclude rw/Anduril --exclude executor/kernelmodule/dwarves --exclude schedules/generatedschedules/ --exclude tracer/target/ -e ssh /home/sebastiaoamaro/phd/rose/ sebasamaro@$1:./torefidevel/

if [ "$#" -eq 2 ]; then
    command="cd torefidevel && vagrant rsync $2"
    ssh sebasamaro@$1 $command
fi
