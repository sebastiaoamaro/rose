set terminal pdf
set xtics font "Helvetica,10"
set size 1,1
set output "overhead.pdf"
load "styles.inc"
set ylabel '% Overhead'
set yrange[:]
#set offset -.3,-.3,0,0
set xtics rotate by 45 right
set style data histogram
set style fill solid 0.5 border
set style histogram clustered
plot "times.data" using ((($4-$2)/$4)*100):xtic(1) title "Overhead" ls 101