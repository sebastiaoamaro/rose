#!/bin/bash
python3 parser.py $1 $2
gnuplot $1plot.gp
gnuplot overhead.gp