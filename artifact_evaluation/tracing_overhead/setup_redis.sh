#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

APT_YES=(-y)
DPKG_NONINTERACTIVE=(
  -o Dpkg::Use-Pty=0
  -o Dpkg::Options::=--force-confdef
  -o Dpkg::Options::=--force-confold
)

echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo -E apt-get install "${APT_YES[@]}" "${DPKG_NONINTERACTIVE[@]}" redis-tools jq redis
sudo -E apt-get update -y update
sudo -E apt-get install "${APT_YES[@]}" "${DPKG_NONINTERACTIVE[@]}" git maven ant vim openjdk-8-jdk
sudo update-alternatives --set java $(sudo update-alternatives --list java | grep "java-8")
sudo -E apt-get upgrade "${APT_YES[@]}" "${DPKG_NONINTERACTIVE[@]}"

export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
echo export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 >> ~/.bashrc
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg

#Sudo for docker
sudo groupadd docker
sudo usermod -aG docker $USER
