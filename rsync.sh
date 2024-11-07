#!/bin/bash
rsync -rav --exclude schedules/generatedschedules/ --exclude rosetracer/target/ --exclude rosetracer/src/bpf/vmlinux.h --exclude tests/bugdetection/ -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@$1:./torefidevel/
#rsync -rav -e ssh /home/sebastiaoamaro/.tmux.conf sebasamaro@vitamina01:./
