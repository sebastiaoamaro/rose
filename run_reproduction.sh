#!/bin/bash

# Check if the number of arguments is exactly 1
if [ "$#" -ne 1 ]; then
  echo "Error: Exactly one argument is required."
  exit 1
fi

# Check if both arguments are not empty
if [ -z "$1" ]; then
  echo "Error: Argument must be non-empty."
  exit 1
fi

# If checks pass, proceed
echo "Arguments provided: $1"

schedule=$1

sudo rm /tmp/containerpid
sudo rm /tmp/history.txt

sudo insmod rose/kernelmodule/rose.ko
python3 schedule_parser.py $schedule
mv faultschedule.c rose/c/
cd rose/c/
make -j$(nproc)
sudo -E ./main/main
