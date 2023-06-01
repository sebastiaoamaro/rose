set terminal pdf
set xtics font "Helvetica,10"
set output "time.pdf"
load "styles.inc"
set ylabel 'Time(seconds)'
#set offset -.3,-.3,0,0
set style data histogram
set style fill solid 0.5 border
set style histogram clustered
plot "times.data" using 2:xtic(1) title "vanilla" ls 101, \
    "times.data" using  3:xtic(1) title "eBPF" ls 102, \
    