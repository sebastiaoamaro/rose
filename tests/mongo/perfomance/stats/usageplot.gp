set terminal pdf
set output 'cpu usage_2.pdf'
load "styles.inc"
set key autotitle columnhead
set key font ",8"
set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 2 replicas'
#use the first and second columns from data file data.data
plot for [i=2:3] "cpu_usage.data" using 0:i with linespoint ps 1 pi -100
plot for [i=10:11] "cpu_usage.data" using 0:i with linespoint ps 1 pi -100



set terminal pdf
set output 'cpu usage_4.pdf'

set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 4 replicas'
#use the first and second columns from data file data.data
plot for [i=4:5] "cpu_usage.data" using 0:i with linespoint ps 1 pi -100
plot for [i=12:13] "cpu_usage.data" using 0:i with linespoint ps 1 pi -100

set terminal pdf
set output 'cpu usage_8.pdf'

set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 8 replicas'
#use the first and second columns from data file data.data
plot for [i=6:7] "cpu_usage.data" using 0:i with linespoint ps 1 pi -100
plot for [i=14:15] "cpu_usage.data" using 0:i with linespoint ps 1 pi -100

set terminal pdf
set output 'cpu usage_16.pdf'

set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 16 replicas'
#use the first and second columns from data file data.data
plot for [i=8:9] "cpu_usage.data" using 0:i with linespoint ps 1 pi -100
plot for [i=16:17] "cpu_usage.data" using 0:i with linespoint ps 1 pi -100
