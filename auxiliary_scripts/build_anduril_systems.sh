#!/bin/bash
cd /vagrant/rw/Anduril/systems/zookeeper-2247
./compile.sh
cd /vagrant/rw/Anduril/systems/zookeeper-3006
./compile.sh
cd /vagrant/rw/Anduril/systems/zookeeper-3157
./compile.sh
cd /vagrant/rw/Anduril/systems/zookeeper-4203
./compile.sh
cd /vagrant/rw/Anduril/systems/hdfs-4233
./compile.sh
cd /vagrant/rw/Anduril/systems/hdfs-12070
./compile.sh
cd /vagrant/rw/Anduril/systems/hdfs-15032
./compile.sh
cd /vagrant/rw/Anduril/systems/hbase-19608
./compile.sh
cd /vagrant/rw/Anduril/systems/kafka-9374
./compile.sh

# cd /vagrant/auxiliary/scripts/
# ./change_java.sh 17
# cd /vagrant/rw/Anduril/systems/hdfs-16332
# ./compile.sh
