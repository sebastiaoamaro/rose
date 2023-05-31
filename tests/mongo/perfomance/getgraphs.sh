#!/bin/bash
rsync -rav -e ssh sebasamaro@proteina06:./torefidevel/tests/mongo/perfomance/stats/*.pdf /home/sebasamaro/phd/torefidevel/tests/mongo/perfomance/graphs/
