#!/bin/bash
rsync -rav --exclude .vagrant/ --exclude rw/Anduril/ --exclude rose/kernelmodule/dwarves --exclude schedules/generatedschedules/ --exclude rosetracer/target/ --exclude tests/bugdetection/ -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@$1:./torefidevel/
#rsync -rav -e ssh /home/sebastiaoamaro/.tmux.conf sebasamaro@$1:./
ssh sebasamaro@proteina05 'cd torefidevel &&vagrant rsync remote'
