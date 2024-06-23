#!/bin/bash
sudo apt-get -y update

sudo apt-get -y upgrade

sudo apt install -y clang libelf1 libelf-dev zlib1g-dev build-essential gcc pkg-config
sudo apt install -y linux-headers-$(uname -r)
sudo apt install python3-pip
pip3 install redis --break-system-packages
curl https://sh.rustup.rs -sSf | sh -s -- -y
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

. "$HOME/.cargo/env"

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get -y install docker-ce docker-ce-cli containerd.io

sudo apt-get -y update

sudo usermod -aG docker $USER

newgrp docker