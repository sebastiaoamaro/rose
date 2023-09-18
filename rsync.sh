#!/bin/bash
rsync -rav -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@saturn2:./torefidevel/
rsync -rav -e ssh /home/sebastiaoamaro/.tmux.conf sebasamaro@saturn2:./