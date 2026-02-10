#!/bin/bash
cd /vagrant/schedules/reproduced_bugs/mongo/mongo_2.4.3/scripts/
./build_images.sh
#Sudo for docker
sudo groupadd docker
sudo usermod -aG docker $USER
