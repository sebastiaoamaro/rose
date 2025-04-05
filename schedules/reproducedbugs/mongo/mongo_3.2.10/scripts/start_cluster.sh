#!/bin/bash
sudo rm -r /mongo_3.2.10_rs/*
cd /vagrant/schedules/reproducedbugs/mongo/mongo_3.2.10/
docker compose -f docker-compose.yaml up -d
sleep 30
docker exec -ti mongo-0 ./start.sh > /tmp/start.log
