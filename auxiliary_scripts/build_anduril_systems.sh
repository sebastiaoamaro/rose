#!/bin/bash
cd /vagrant/rw/Anduril/systems/zookeeper-2247
./compile.sh
/vagrant/rw/Anduril/ground_truth/zookeeper-2247/run-original-test.sh

cd /vagrant/rw/Anduril/systems/zookeeper-3006
./compile.sh
/vagrant/rw/Anduril/experiment/zookeeper-3006/run-original-test.sh

cd /vagrant/rw/Anduril/systems/zookeeper-3157
./compile.sh
/vagrant/rw/Anduril/ground_truth/zookeeper-3157/run-original-test.sh

cd /vagrant/rw/Anduril/systems/zookeeper-4203
./compile.sh
/vagrant/rw/Anduril/ground_truth/zookeeper-4203/run-original-test.sh

cd /vagrant/rw/Anduril/systems/hdfs-4233
./compile.sh
cd /vagrant/rw/Anduril/systems/hdfs-12070
./compile.sh
/vagrant/rw/Anduril/experiment/hdfs-12070/run-original-test.sh

cd /vagrant/rw/Anduril/systems/hdfs-15032
./compile.sh
/vagrant/rw/Anduril/experiment/hdfs-15032/run-original-test.sh

cd /vagrant/rw/Anduril/systems/hbase-19608
./compile.sh
/vagrant/rw/Anduril/experiment/hbase-19608/run-original-test.sh

cd /vagrant/rw/Anduril/systems/kafka-12508
./compile.sh
 /vagrant/rw/Anduril/experiment/kafka-12508/run-original-test.sh

cd /vagrant/auxiliary_scripts/
./change_java.sh 17
cd /vagrant/rw/Anduril/systems/hdfs-16332
./compile.sh
/vagrant/rw/Anduril/experiment/hdfs-16332/run-original-test.sh
