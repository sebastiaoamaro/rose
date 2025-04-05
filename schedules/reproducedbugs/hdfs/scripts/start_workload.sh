#!/bin/bash
cd /vagrant/rw/Anduril/experiment/hdfs-4233/cluster
workspace=$(pwd)
INJECT_HADOOP_OPTS="-DflakyAgent.distributedMode=true -DflakyAgent.disableAgent=false $INJECT_HADOOP_OPTS"
HADOOP_OPTS="-DflakyAgent.distributedMode=true -DflakyAgent.disableAgent=true"
HADOOP_CLASSPATH="$HADOOP_CLASSPATH"
JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
for i in 1 2 3 4; do
  pid=`cat $workspace/logs-1/*.pid`
  if [ $(ps -p $pid | wc -l) -eq 1 ]; then
    echo "namenode failed"
    HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$HADOOP_OPTS" $workspace/stop-cluster.sh
    exit 0
  fi
  JAVA_HOME="$JAVA_HOME" HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$HADOOP_OPTS" $workspace/client.sh -mkdir /"client"$i &
  pid=$!
  for j in {0..5}; do
    sleep 1
    if [ $(ps -p $pid | wc -l) -eq 1 ]; then
      break
    fi
  done
  if [ $(ps -p $pid | wc -l) -gt 1 ]; then
    echo "some client gets stuck"
    kill -9 $pid
    HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$HADOOP_OPTS" $workspace/stop-cluster.sh
    exit 0
  fi
done
