set terminal pdf
set xtics font "Helvetica,10"
set size 1,1
set output "time.pdf"
load "styles.inc"
set ylabel 'Time(seconds)'
set yrange[0:]
#set offset -.3,-.3,0,0
set xtics rotate by 45 right
set style data histogram
set style fill solid 0.5 border
set style histogram clustered errorbars
plot "times.data" using 2:3:xtic(1) title "vanilla" ls 101, \
    "times.data" using  4:5:xtic(1) title "eBPF" ls 102, \
    