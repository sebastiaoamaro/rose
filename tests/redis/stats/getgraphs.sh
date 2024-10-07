#!/bin/bash
rsync -rav -e ssh sebasamaro@proteina03:./torefidevel/tests/redis/stats/*.pdf /home/sebastiaoamaro/phd/torefidevel/tests/redis/graphs/

#rsync -rav -e ssh sebasamaro@vitamina01:./torefidevel/tests/mongo/perfomance/stats/times*.txt /home/sebastiaoamaro/phd/torefidevel/tests/mongo/perfomance/graphs/
