set terminal pdf
set output 'cpu usage_3.pdf'
load "styles.inc"

set yrange[0:]

set key autotitle columnhead
set key font ",8"
set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 3 replicas'
plot "cpu_usage.data" using 2 smooth csplines , \
    '' using 3 smooth csplines , \
    '' using 8 smooth csplines , \
    '' using 9 smooth csplines 



set output 'cpu usage_6.pdf'
set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 6 replicas'
plot "cpu_usage.data" using 4 smooth csplines , \
    '' using 5 smooth csplines , \
    '' using 10 smooth csplines , \
    '' using 11 smooth csplines 

set output 'cpu usage_12.pdf'

set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 12 replicas'
plot "cpu_usage.data" using 6 smooth csplines , \
    '' using 7 smooth csplines , \
    '' using 12 smooth csplines , \
    '' using 13 smooth csplines 
