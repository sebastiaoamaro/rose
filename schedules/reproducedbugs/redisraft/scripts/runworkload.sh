#!/bin/bash
exec  -a "$0" docker exec -dt client python3 workload.py 1000000
