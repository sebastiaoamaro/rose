#!/bin/bash
rsync -rav --exclude rw/ --exclude rose/kernelmodule/dwarves --exclude schedules/generatedschedules/ --exclude rosetracer/target/ --exclude rosetracer/src/bpf/vmlinux.h --exclude tests/bugdetection/ -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@$1:./torefidevel/
#rsync -rav -e ssh /home/sebastiaoamaro/.tmux.conf sebasamaro@$1:./
