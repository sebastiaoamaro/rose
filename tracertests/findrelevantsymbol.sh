#!/bin/bash
source ./stats_collector.sh

python3 remove_probes.py "/tmp/uprobe_stats.txt" $elapsed_time $functions_file
