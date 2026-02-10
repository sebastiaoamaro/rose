#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/schedules/reproduced_bugs/redisraft
sudo docker compose -f setup/composedfd91d4.yaml up -d
