#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/schedules/bug_discovery/redis_setup/
sudo /vagrant/schedules/bug_discovery/redis_setup/setup.sh 3
docker compose -f docker-compose.yaml up -d

echo "Script Finished"
