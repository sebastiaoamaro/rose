#!/bin/bash
sudo rm -r /redis/*
cd /vagrant/artifact_evaluation/tracing_overhead/trace_size/
sudo /vagrant/schedules/bug_discovery/redis_setup/setup.sh 3
docker compose -f docker-compose.yaml up -d
