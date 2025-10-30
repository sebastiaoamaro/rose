#!/bin/bash
#exec -a "$0" docker exec -dt client python3 workload.py 1000000
exec -a "$0" nsenter -t $(docker inspect -f '{{.State.Pid}}' client) -a python3 workload.py 1000000 > output.log 2>&1
