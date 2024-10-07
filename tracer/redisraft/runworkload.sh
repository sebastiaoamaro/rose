#!/bin/bash
exec  -a "$0" docker exec -ti client python3 workload.py 10000
