#!/bin/bash
sudo insmod rose/kernelmodule/rose.ko
sudo rm /tmp/history.txt
sudo rm /tmp/containerpid
python3 schedule_parser.py $1
mv faultschedule.c rose/c/
cd rose/c/
make
sudo ./main/main