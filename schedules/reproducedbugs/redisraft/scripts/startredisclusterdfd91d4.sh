#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/schedules/reproducedbugs/redisraft
docker compose -f setup/composedfd91d4.yaml up -d
