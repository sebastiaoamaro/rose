set terminal pdf
set output 'cpu usage_2_4.pdf'
load "styles.inc"
set key autotitle columnhead
set key font ",8"
set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys dstat eBPF'
#use the first and second columns from data file data.data
plot for [i=2:9] "cpu_usage.data" using 0:i with linespoint ps 1 pi -25

set terminal pdf
set output 'cpu usage_8_16.pdf'

set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys dstat vanilla'
#use the first and second columns from data file data.data
plot for [i=10:17] "cpu_usage.data" using 0:i with linespoint ps 1 pi -25

set terminal pdf
set output 'cpu usage_all.pdf'
set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys dstat'
#use the first and second columns from data file data.data
plot for [i=2:17] "cpu_usage.data" using 0:i with linespoint ps 1 pi -25