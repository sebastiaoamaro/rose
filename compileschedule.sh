#!/bin/bash
sudo rm /tmp/containerpid
python3 rose/faultscheduleparser.py $1
mv faultschedule.c rose/c/
cd rose/c/
make;


if [ $# -gt 1 ]; then
  echo "Moved to: $2"
  cp ./main/main $2/rose
  # Do something with the argument
else
  echo "No arguments provided."
fi
