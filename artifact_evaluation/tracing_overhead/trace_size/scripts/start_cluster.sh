#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/tests/redis
sudo /vagrant/artifact_evaluation/tracing_overhead/throughput/configs/setup.sh 3
docker compose -f /vagrant/artifact_evaluation/tracing_overhead/throughput/configs/docker-compose3.yaml up -d
sleep 30
redis-cli --cluster create $(cat configs/ips3.txt) --cluster-yes
sleep 30
