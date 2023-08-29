#!/bin/bash
sudo python3 parser.py $1 $2
gnuplot -e  "outputname='$2".pdf"';inputname='times"$2".data'" perfomanceplot.gp 