#!/bin/bash

#This should work but it does not

# cd /vagrant/rw/Anduril/experiment/hdfs-4233/cluster
# workspace=$(pwd)

# INJECT_HADOOP_OPTS="-DflakyAgent.distributedMode=true -DflakyAgent.disableAgent=false $INJECT_HADOOP_OPTS"
# HADOOP_OPTS="-DflakyAgent.distributedMode=true -DflakyAgent.disableAgent=true"
# HADOOP_CLASSPATH="$HADOOP_CLASSPATH"
# JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
# JAVA_HOME="$JAVA_HOME"

# HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$HADOOP_OPTS" $workspace/stop-namenode.sh 1 1
# HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$HADOOP_OPTS" $workspace/stop-secondarynamenode.sh 0 0
# HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$HADOOP_OPTS" $workspace/stop-datanode.sh 2 2
# HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$HADOOP_OPTS" $workspace/stop-datanode.sh 3 3

sudo kill -9 $(pgrep -f "DflakyAgent")
