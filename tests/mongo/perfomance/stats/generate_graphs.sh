#!/bin/bash
sudo python3 parser.py $1
gnuplot $1plot.gp