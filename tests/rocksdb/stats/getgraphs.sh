#!/bin/bash
rsync -rav -e ssh sebasamaro@proteina06:./torefidevel/tests/rocksdb/stats/*.pdf /home/sebasamaro/phd/torefidevel/tests/rocksdb/graphs/
