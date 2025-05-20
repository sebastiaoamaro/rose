#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/schedules/reproducedbugs/redisraft
docker compose -f setup/compose2d1cf30.yaml up -d
