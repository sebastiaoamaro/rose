set terminal pdf
set output 'cpu usage_2.pdf'
load "styles.inc"

set yrange[0:]

set key autotitle columnhead
set key font ",8"
set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 2 replicas'
plot "cpu_usage.data" using 2 smooth csplines , \
    '' using 3 smooth csplines , \
    '' using 10 smooth csplines , \
    '' using 11 smooth csplines 



set output 'cpu usage_4.pdf'
set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 4 replicas'
plot "cpu_usage.data" using 4 smooth csplines , \
    '' using 5 smooth csplines , \
    '' using 12 smooth csplines , \
    '' using 13 smooth csplines 

set output 'cpu usage_8.pdf'

set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 8 replicas'
plot "cpu_usage.data" using 6 smooth csplines , \
    '' using 7 smooth csplines , \
    '' using 14 smooth csplines , \
    '' using 15 smooth csplines 

set output 'cpu usage_16.pdf'

set rmargin 15
set key at screen 1,graph 1
set xlabel 'Time (seconds)'
set ylabel 'CPU %'
set title 'CPU usr + sys 16 replicas'
plot "cpu_usage.data" using 8 smooth csplines, \
    '' using 9 smooth csplines, \
    '' using 16 smooth csplines, \
    '' using 17 smooth csplines
