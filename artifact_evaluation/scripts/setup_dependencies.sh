#!/bin/bash
mkdir /vagrant/rw/Anduril/
cd /vagrant/auxiliary_scripts/
./install.sh
cd /vagrant/
pip3 install -e . --break-system-packages
mkdir /vagrant/tests/bugdetection/
mkdir /vagrant/tests/bugdetection/hbase
mkdir /vagrant/tests/bugdetection/hdfs
mkdir /vagrant/tests/bugdetection/kafka
mkdir /vagrant/tests/bugdetection/mongo
mkdir /vagrant/tests/bugdetection/redis
mkdir /vagrant/tests/bugdetection/redisraft
mkdir /vagrant/tests/bugdetection/tendermint
mkdir /vagrant/tests/bugdetection/zookeeper
