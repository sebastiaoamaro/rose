#!/bin/bash
sudo apt-get -y install redis-tools jq
sudo apt-get -y update
sudo apt install -y git maven ant vim openjdk-8-jdk
sudo update-alternatives --set java $(sudo update-alternatives --list java | grep "java-8")
sudo apt-get -y upgrade

export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
echo export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 >> ~/.bashrc