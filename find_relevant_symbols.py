import random
import yaml
import signal
import sys
import subprocess
from processor.processor import History, choose_faults, compare_faults, write_new_schedule
from processor.binary_parser import calculate_offsets
from parser.conditions import file_syscall_condition, syscall_condition, time_cond, user_function_condition
import shutil
import time
import math
from copy import deepcopy
import os
from reproduce_bug import BugReproduction, parse_bug_reproduction,run_reproduction,run_cleanup,collect_history,Run
from pathlib import Path

def parse_file_split_by_comma(file_path, skip_empty=True, strip_items=True):

    file_path = Path(file_path)
    if not file_path.exists():
        print("File {} does not exist".format(file_path))
        return []

    with open(file_path, 'r') as file:
        lines = []
        for line in file:
            if skip_empty and not line.strip():
                continue
            items = line.strip().split(',')
            if strip_items:
                items = [item.strip() for item in items]
            lines.append(items)
        return lines

def delete_function_from_file(filename: str, target: str) -> None:
    with open(filename, 'r') as file:
        lines = file.readlines()

    with open(filename, 'w') as file:
        for line in lines:
            if target not in line:
                file.write(line)

def main():
    filename = sys.argv[1]
    bug_reproduction = parse_bug_reproduction(filename)
        #cleanup last runs
    try:
        os.remove("/tmp/failed_probes.txt")
    except FileNotFoundError:
        print("Failed to remove failed_probes not found")
    except PermissionError:
        print("Failed to remove files no perms")
    try:
        os.remove("/tmp/function_stats.txt")
    except FileNotFoundError:
        print("Failed to remove function_stats not found")
    except PermissionError:
        print("Failed to remove files no perms")

    bug_reproduction = parse_bug_reproduction(filename)
    #Run faultless schedule
    start_time = time.time()
    print("Running faultless schedule")
    run_reproduction(bug_reproduction.schedule)
    trace_location = collect_history(bug_reproduction.trace_location,bug_reproduction.result_folder,"normal")
    run_cleanup(bug_reproduction.cleanup)
    end_time = time.time()
    elapsed_time = end_time - start_time

    failed_probes = parse_file_split_by_comma("/tmp/failed_probes.txt")

    function_stats = parse_file_split_by_comma("/tmp/function_stats.txt")

    frequent_functions = []
    for function in function_stats:
        ratio = int(function[2])/elapsed_time
        print("Ratio is {}, total calls is {} time_elasped is {}".format(ratio, function[2],elapsed_time))
        if ratio >2:
            frequent_functions.append(function[0])


    for frequent_function in frequent_functions:
        print(f"Removing function {frequent_function}")
        delete_function_from_file(bug_reproduction.functions_file, frequent_function)

if __name__ == "__main__":
    main()
