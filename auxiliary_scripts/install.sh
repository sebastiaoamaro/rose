#!/bin/bash
sudo apt-get update
sudo apt-get -y install clang libelf1 libelf-dev zlib1g-dev libc6-dev-i386 autoconf make python3-pip pcp gnuplot gcc pkg-config gcc-14 cmake llvm jq
sudo apt-get upgrade

#Docker
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run hello-world

sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker

#RUST
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"

#Github
sudo apt install git


#Kernel module
cd rose/kernelmodule
sudo apt-get install -y libdw1 dwarves elfutils libdw-dev pahole libdwarf-dev
cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/
git clone https://github.com/acmel/dwarves.git
cd dwarves
git submodule update --init --recursive
mkdir build
cd build
cmake ..
make install
cd ../../

#bpftool

cd bpftool
git pull

cd libbbpf
git checkout master
git pull
make
cd ..
cd src
make
sudo make install
cd ../..

#Anduril
# sudo apt-get update
# sudo apt install git maven ant vim openjdk-8-jdk
# sudo update-alternatives --set java $(sudo update-alternatives --list java | grep "java-8")

# export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
# echo export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 >> ~/.bashrc

#Build vmlinux.h

cd rosetracer/src/bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h