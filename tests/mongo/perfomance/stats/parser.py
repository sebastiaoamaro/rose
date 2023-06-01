import pandas
import subprocess

from os import listdir
from os.path import isfile
from statistics import mean

from datetime import datetime

def parse_usages():
    files = [f for f in listdir(".") if isfile(f)]

    statfiles = [f for f in files if "stats" in f and ".txt" in f]

    all_usages_usr = {}
    all_usages_sys = {}

    filenames_simple = []

    #Workloads may vary on time
    max_len_collected = -1

    now = datetime.now()

    current_time = now.strftime("%H:%M:%S")


    for filename in statfiles:

        filename_simple = filename[:len(filename)-4]
        filenames_simple.append(filename_simple)

        filenamecsv = filename_simple + str(".csv")

        file = open(filename)
        filecsv= open(filenamecsv,'w')

        filelines = file.readlines()

        for i in range(5,len(filelines)):
            filecsv.write(filelines[i])

        filecsv.close()
        file.close()

        result = pandas.read_csv(filenamecsv)


        usr_usage = result["total usage:usr"]

        sys_usage = result["total usage:sys"]

        all_usages_usr[filename_simple] = usr_usage
        all_usages_sys[filename_simple] = sys_usage

        if len(usr_usage) > max_len_collected:
            max_len_collected = len(usr_usage)

        # print(result)


    file_cpu_usage = open("cpu_usage" + str(current_time) + ".data","w")

    line = 0
    file_cpu_usage.write("time ")

    #Sorty by number of replicas
    def sorting(key):
        if key[-2].isdigit():
            return int(key[-1]) + 10*int(key[-2])
        else:
            return int(key[-1])

    #Sort by ebpf
    def sortbyebpf(key):
        return key[6]

    filenames_simple_sorted = sorted(filenames_simple,key=sorting)
    filenames_sortby_bpf = sorted(filenames_simple_sorted,key=sortbyebpf)

    #Create first row with files
    for filename in filenames_sortby_bpf:
        file_cpu_usage.write(filename + "usr" + " ")
        file_cpu_usage.write(filename + "sys" + " ")

    file_cpu_usage.write("\n")

    #Populate .data
    for i in range(0,max_len_collected):
        file_cpu_usage.write(str(i))
        file_cpu_usage.write(" ")
        for filename in filenames_sortby_bpf:
            if len(all_usages_usr[filename]) <= i:
                file_cpu_usage.write("?" + " " + "?" + " ")
            else:
                file_cpu_usage.write(str(all_usages_usr[filename][i]) + " " + str(all_usages_sys[filename][i]) + " ")
        file_cpu_usage.write("\n")

    file_cpu_usage.close()
    


def parse_perfomance():
    times = open("times.txt")
    times_data = open("times.data","w")

    times_lines = times.readlines()

    dict_times = {}
    for line in times_lines:
        params = line.split(":")
        key = params[1] + params[2]
        if key in dict_times:
            dict_times[key].append(float(params[3][:-1]))
        else:
            dict_times[key] = []
            dict_times[key].append(float(params[3][:-1]))
    
    times.close()

    output_arrays = []

    for i in range(0,16):
        output_arrays.append([0]*2)

    for key,value in dict_times.items():
        if key[0] == "v":
            output_arrays[int(key[1])-1][0] = mean(value)
        else:
            output_arrays[int(key[1])-1][1] = mean(value)


    times_data.write(" " + "vanilla" + " " + "eBPF" + "\n")
    line_count = 0
    print(output_arrays)

    for list in output_arrays:
        if list[0] == 0 or list[1] == 0:
            line_count+=1
            continue
        times_data.write(str(line_count+1) + " " + str(list[0]) + " " + str(list[1]) + "\n")
        line_count+=1
    return

import sys
def main():
    if sys.argv[1] == "usage":
        parse_usages()
    if sys.argv[1] == "perfomance":
        parse_perfomance()
    
if __name__ == "__main__":
    main()