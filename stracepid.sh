#!/bin/bash
sudo rm output.txt
sudo strace -p $1 -o output.txt