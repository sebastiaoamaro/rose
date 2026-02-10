#!/bin/bash
sudo rm -r /mongo_2.4_rs/*
cd /vagrant/schedules/reproduced_bugs/mongo/mongo_2.4.3/
sudo docker compose -f docker-compose.yaml up -d
sleep 30
sudo docker exec -ti mongo-0 ./start.sh > /tmp/start.log
