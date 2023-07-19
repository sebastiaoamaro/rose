#!/bin/bash
sudo apt-get -y install clang libelf1 libelf-dev zlib1g-dev libc6-dev-i386 autoconf make python3-pip pcp gnuplot gcc
sudo pip3 install pymongo==3.12.0 pandas
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

##Docker
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run hello-world

sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker

##Rocks
git clone https://github.com/facebook/rocksdb.git
cd rocksdb
make static_lib
cd examples
make all