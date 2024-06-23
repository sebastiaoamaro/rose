#!/bin/bash
rsync -rav --exclude rosetracer/target/ --exclude rosetracer/src/bpf/vmlinux.h -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@proteina03:./torefidevel/
#rsync -rav -e ssh /home/sebastiaoamaro/.tmux.conf sebasamaro@vitamina01:./