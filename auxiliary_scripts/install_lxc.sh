#!/bin/bash
sudo apt update -y
sudo apt install -y lxc lxc-utils lxcfs bridge-utils uidmap
sudo apt install -y openjdk-17-jdk libjna-java gnuplot graphviz
sudo update-alternatives --set java $(update-alternatives --list java | grep "17" | head -1)
sudo mv lein /usr/local/bin
lxd init --preseed < lxd_config.yaml
