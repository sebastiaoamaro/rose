#!/bin/bash
sudo docker build -f ../Dockerfile_mongo . -t custom_mongo:2.4.3
sudo docker build -f ../Dockerfile_client . -t mongo_client:2.4.3
