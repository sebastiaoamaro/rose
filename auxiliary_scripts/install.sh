#!/bin/bash

###############################################################
#### AFTER RUNNING THIS SCRIPT, PLEASE REBOOT YOUR MACHINE ####
###############################################################
cp tmux.conf ~/.tmux.conf
echo -e '\n# Set default working directory\nexport WORKDIR="/vagrant" && [ -d "$WORKDIR" ] && cd "$WORKDIR" || echo "Directory $WORKDIR not found"' >> ~/.bashrc

cd ..
echo "Updating git submodules..."
git submodule update --init --recursive > /dev/null
echo "Updating package list..."
cd auxiliary_scripts/

cp tmux.conf ~/.tmux.conf
sudo apt-get update
sudo apt-get -y install clang libelf1 libelf-dev zlib1g-dev libc6-dev-i386 autoconf make python3-pip pcp gnuplot gcc pkg-config gcc-14 cmake llvm jq linux-headers-$(uname -r)
sudo apt-get  -y upgrade

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

#RUST
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup install 1.86.0
rustup override set 1.86.0


#Github
sudo apt install git

#Kernel module
echo "Setting up kernel module dependencies..."
cd ..
cd executor/kernelmodule
sudo apt-get -qq install -y libdw1 dwarves elfutils libdw-dev pahole libdwarf-dev
sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/
# dwarves is already a submodule, no need to clone manually
echo "Building dwarves..."
cd dwarves
git config --global --add safe.directory /rose/executor/kernelmodule/dwarves
git submodule update --init --recursive > /dev/null
mkdir -p build
cd build
cmake .. > /dev/null
make > /dev/null
sudo make install > /dev/null
sudo ldconfig
cd ../../../../auxiliary_scripts

#libbpf
echo "Building libbpf..."
cd ../libbpf/src
make > /dev/null
sudo make install
cd ../../auxiliary_scripts

#bpftool
echo "Setting up bpftool..."
cd ../bpftool
git reset --hard HEAD > /dev/null 2>&1 || true
git submodule update --init --recursive > /dev/null

cd libbpf
git checkout master > /dev/null 2>&1 || git checkout -b master > /dev/null
git pull origin master > /dev/null 2>&1 || true
cd src
echo "Building libbpf for bpftool..."
make clean > /dev/null
make > /dev/null

echo "DIRECTORY:"$(pwd)
cd ../..
cd src
echo "Building bpftool..."
make clean > /dev/null
make > /dev/null
sudo make install
export PATH=/usr/local/bin:$PATH
cd ../../auxiliary_scripts

#Anduril
sudo apt-get update
sudo apt install -y git maven ant vim openjdk-8-jdk
sudo update-alternatives --set java $(sudo update-alternatives --list java | grep "java-8")

export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
echo export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 >> ~/.bashrc

#Build vmlinux.h
cd ../
cd tracer/src/bpf
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

cd ../../
cargo build --release


# #Sudo for docker
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
