#!/bin/bash
sudo rm -r /mongo_3.2.10_rs/*
cd /vagrant/schedules/reproduced_bugs/mongo/mongo_3.2.10/
sudo docker compose -f docker-compose.yaml up -d
sleep 30
sudo docker exec -ti mongo-0 ./start.sh > /tmp/start.log
