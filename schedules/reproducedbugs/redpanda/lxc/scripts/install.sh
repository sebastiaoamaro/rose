#!/bin/bash
sudo apt update
sudo apt install lxc lxc-utils lxcfs bridge-utils uidmap
sudo apt install openjdk-17-jdk libjna-java gnuplot graphviz
./create_ssh_keys.sh
mv lein /usr/local/bin
