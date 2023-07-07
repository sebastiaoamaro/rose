#!/bin/bash
rsync -rav -e ssh sebasamaro@proteina06:./torefidevel/tests/mongo/perfomance/stats/*.pdf /home/sebastiaoamaro/phd/torefidevel/tests/mongo/perfomance/graphs/
