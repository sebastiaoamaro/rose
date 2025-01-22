#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/schedules/reproducedbugs/redisraft
docker compose -f setup/composeissue43.yaml up -d