#!/bin/bash
rsync -rav -e ssh /home/sebastiaoamaro/phd/torefidevel/ sebasamaro@vitamina01:./torefidevel/
rsync -rav -e ssh /home/sebastiaoamaro/.tmux.conf sebasamaro@vitamina01:./