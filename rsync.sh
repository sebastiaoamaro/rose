#!/bin/bash
rsync -rav --exclude rosetracer/target/ --exclude rosetracer/src/bpf/vmlinux.h -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@proteina01:./torefidevel/
rsync -rav -e ssh /home/sebastiaoamaro/.tmux.conf sebasamaro@proteina01:./