#!/bin/bash
cd /vagrant/schedules/reproduced_bugs/redisraft/setup/
./build_images.sh
#Sudo for docker
sudo groupadd docker
sudo usermod -aG docker $USER
