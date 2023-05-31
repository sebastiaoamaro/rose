#!/bin/bash
rsync -rav -e ssh /home/sebasamaro/phd/torefidevel/ sebasamaro@proteina06:./torefidevel/
#rsync -rav -e ssh /home/sebasamaro/.tmux.conf sebasamaro@proteina06:./