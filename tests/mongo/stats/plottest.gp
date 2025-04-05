# vi: set ft=gnuplot :

set title font "Helvetica,20"
set key left top Left

set terminal postscript color eps enhanced 22

set size 1,0.85


filename='faults.eps'
set output filename

set style line 2 lc rgb 'black' lt 1 lw 1
#set style data histogram
#set style histogram cluster gap 1
#set style fill solid border -1
#set boxwidth 0.9
set grid ytics

ylabel='Throughput (tx/sec)'
set ylabel ylabel
set xrange [0:60]
set yrange [0:500]
set xlabel "Time (sec)"
#set style line 0 lc rgb 'gray30' lt 1 lw 2
#set style line 2 lc rgb 'gray60' lt 1 lw 2
#set style line 3 lc rgb 'gray90' lt 1 lw 2


title='Recovery Time'
set title title
set style data lines

set samples 300, 300
set xrange [ 0 : * ] noreverse writeback
set x2range [ 0 : * ] noreverse writeback
set yrange [ 0 : 300 ] noreverse writeback
set y2range [ 0 : * ] noreverse writeback
set zrange [ * : * ] noreverse writeback
set cbrange [ * : * ] noreverse writeback
set rrange [ * : * ] noreverse writeback
set xtics 0,5,60

#set style line 0 lc rgb 'gray30' lt 1 lw 2
#set style line 2 lc rgb 'gray60' lt 1 lw 2
#set style line 3 lc rgb 'gray90' lt 1 lw 2
plot 'faults-combined.dat' using 1:2 lt rgb 'gray30' lw 5 smooth csplines title "Cassandra", \
            '' using 1:3 lt rgb 'gray60' lw 5 smooth csplines title "SconeKV", \
            '' using 1:4 lt rgb 'gray90' lw 5 smooth csplines title "CockroachDB"