#!/bin/bash

# docker build -f Dockerfiles/Dockerfile21.8.1 -t redpanda21.8.1 .
# docker build -f Dockerfiles/Dockerfile21.9.6 -t redpanda21.9.6 .
docker build -f Dockerfiles/Dockerfile21.10.1 -t redpanda21.10.1 .
# docker build -f Dockerfiles/DockerfileRecent -t redpandarecent .

docker build -f client/Dockerfile -t client .