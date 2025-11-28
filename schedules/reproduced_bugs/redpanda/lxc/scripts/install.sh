#!/bin/bash
sudo apt update
sudo apt install lxc lxc-utils lxcfs bridge-utils uidmap
sudo apt install openjdk-17-jdk libjna-java gnuplot graphviz
sudo update-alternatives --set java $(update-alternatives --list java | grep "17" | head -1)
sudo ./create_ssh_key.sh
sudo mv lein /usr/local/bin
lxd init
