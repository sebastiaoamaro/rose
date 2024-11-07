#!/bin/bash
sudo rm /tmp/containerpid
python3 rose/parser/faultscheduleparser.py $1
mv faultschedule.c rose/c/
cd rose/c/
make;
sudo ./main/main -v
