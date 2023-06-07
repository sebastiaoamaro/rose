import pandas
import subprocess

from os import listdir
from os.path import isfile
from statistics import mean,stdev

from datetime import datetime
    

def parse_perfomance(filename):
    times = open(filename)
    times_data = open("times.data","w")

    times_lines = times.readlines()

    dict_times = {}
    for line in times_lines:
        params = line.split(":")
        key = params[1]
        if key in dict_times:
            dict_times[key].append(float(params[2][:-1]))
        else:
            dict_times[key] = []
            dict_times[key].append(float(params[2][:-1]))
    
    times.close()

    output_arrays = [0,0,0,0]

    for key,value in dict_times.items():
        if key[0] == "v":
            output_arrays[0] = mean(value)
            output_arrays[1] = stdev(value)

        else:
            output_arrays[2] = mean(value)
            output_arrays[3] = stdev(value)



    times_data.write("#Replicacount " + "vanilla" + " " + "eBPF" + "\n")
    line_count = 0
    print(output_arrays)

    times_data.write(str(line_count+1) + " " + str(output_arrays[0]) + " " + str(output_arrays[1]) + " " + str(output_arrays[2]) + " " + str(output_arrays[3]) + "\n")

    return

import sys
def main():
    if sys.argv[1] == "perfomance":
        parse_perfomance(sys.argv[2])
    
if __name__ == "__main__":
    main()