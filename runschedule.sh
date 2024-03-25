#!/bin/bash
python3 faultscheduleparser.py $1
mv faultschedule.c examples/c/
cd examples/c/
make;
sudo ./main/main -v