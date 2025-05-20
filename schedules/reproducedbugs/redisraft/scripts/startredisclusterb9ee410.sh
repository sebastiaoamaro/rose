#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/schedules/reproducedbugs/redisraft
docker compose -f setup/composeb9ee410.yaml up -d
