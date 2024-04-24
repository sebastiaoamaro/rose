#!/bin/bash
python3 parser/faultscheduleparser.py $1
mv faultschedule.c rose/c/
cd rose/c/
make;
sudo ./main/main -v