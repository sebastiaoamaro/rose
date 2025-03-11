#!/bin/bash
#cd /vagrant/rw/Anduril/experiment/hdfs-4233/cluster
cd /home/sebastiaoamaro/phd/torefidevel/rw/Anduril/evaluation/hdfs-4233/cluster/
workspace=$(cd "$(dirname "${BASH_SOURCE-$0}")"; pwd)
INJECT_HADOOP_OPTS="-DflakyAgent.distributedMode=true -DflakyAgent.disableAgent=false $INJECT_HADOOP_OPTS"
HADOOP_OPTS="-DflakyAgent.distributedMode=true -DflakyAgent.disableAgent=true"
HADOOP_CLASSPATH="$HADOOP_CLASSPATH"

$workspace/setup.sh
cp -r $workspace/init-store/current $workspace/store-1/

HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$INJECT_HADOOP_OPTS" $workspace/start-cluster.sh
