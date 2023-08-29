import pandas
import subprocess

from os import listdir
from os.path import isfile
from statistics import mean,stdev

from datetime import datetime
    

def parse_perfomance(filename,call_interval):
    times = open(filename)
    times_data = open("times" + call_interval + ".data","w")

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

    output_arrays = [0,0,0,0,0,0,0,0]

    for key,value in dict_times.items():
        if key == "v":
            output_arrays[0] = mean(value)
            output_arrays[1] = stdev(value)
        if key == "u":
            output_arrays[2] = mean(value)
            output_arrays[3] = stdev(value)
        if key == "uf":
            output_arrays[4] = mean(value)
            output_arrays[5] = stdev(value)
        if key == "a":
            output_arrays[6] = mean(value)
            output_arrays[7] = stdev(value)


    times_data.write("#Replicacount " + "vanilla" + " " + "uprobes only" + " " + "uprobes and fault"+ " " + "all" + "\n")
    line_count = 0
    print(output_arrays)

    times_data.write(str(line_count+1) + 
                     " " + str(output_arrays[0]) + " " + str(output_arrays[1]) + 
                     " " + str(output_arrays[2]) + " " + str(output_arrays[3]) + 
                     " " + str(output_arrays[4]) + " " + str(output_arrays[5]) + 
                     " " + str(output_arrays[6]) + " " + str(output_arrays[7]) + 
                     "\n")

    return

import sys
def main():
    print(sys.argv[1] + " " + sys.argv[2])
    parse_perfomance(sys.argv[1],sys.argv[2])
    
if __name__ == "__main__":
    main()