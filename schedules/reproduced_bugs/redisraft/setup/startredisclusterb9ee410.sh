#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/schedules/reproduced_bugs/redisraft
sudo docker compose -f setup/composeb9ee410.yaml up -d
