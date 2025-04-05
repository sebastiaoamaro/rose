#!/usr/bin/env bash
cd /vagrant/rw/Anduril/experiment/hdfs-4233/cluster
INJECT_HADOOP_OPTS="-DflakyAgent.distributedMode=true -DflakyAgent.disableAgent=false $INJECT_HADOOP_OPTS"
HADOOP_OPTS="-DflakyAgent.distributedMode=true -DflakyAgent.disableAgent=true"
HADOOP_CLASSPATH="$HADOOP_CLASSPATH"
JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
workspace=$(pwd)
JAVA_HOME="$JAVA_HOME" HADOOP_CLASSPATH="$HADOOP_CLASSPATH" HADOOP_OPTS="$HADOOP_OPTS -DflakyAgent.pid=1" exec -a "$0" $workspace/start-namenode.sh 1 1
