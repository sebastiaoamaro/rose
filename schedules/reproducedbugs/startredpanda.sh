#!/bin/bash
cd /home/sebastiaoamaro/phd/redpanda/
rm output.txt
docker compose -f configs/redpanda21.10.1.yml up >> output.txt &