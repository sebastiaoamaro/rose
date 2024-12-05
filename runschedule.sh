#!/bin/bash
sudo insmod rose/kernelmodule/rose.ko
sudo rm /tmp/containerpid
python3 rose/faultscheduleparser.py $1
mv faultschedule.c rose/c/
cd rose/c/
make;
sudo ./main/main -v
