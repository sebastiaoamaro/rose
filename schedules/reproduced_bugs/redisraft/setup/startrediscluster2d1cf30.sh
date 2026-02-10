#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/schedules/reproduced_bugs/redisraft
sudo docker compose -f setup/compose2d1cf30.yaml up -d
