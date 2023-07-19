#!/bin/bash
maindirectory=/home/sebastiaoamaro/phd/torefidevel/examples/c/main/
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
faultsfile=$maindirectory/"faults.txt"
cd /home/sebastiaoamaro/phd/torefidevel/examples/c
make
cd $SCRIPT_DIR

cd /home/sebastiaoamaro/phd/cometbft/build
rm output.txt
rm $faultsfile
./cometbft init
./cometbft node --proxy_app kvstore >> output.txt&
comet_PID=$!

echo $comet_PID";" >> $faultsfile

sudo $maindirectory/main -f 1 -d 0 -i $faultsfile

sudo kill $comet_PID