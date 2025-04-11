import random
from types import new_class
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
from reproduce_bug import BugReproduction, parse_bug_reproduction,run_reproduction,run_cleanup,collect_history,Run

def parse_file_split_by_comma(file_path, skip_empty=True, strip_items=True):
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

def main():
    filename = sys.argv[1]
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
    print(failed_probes)

    function_stats = parse_file_split_by_comma("/tmp/function_stats.txt")
    print(function_stats)

    frequent_functions = []
    for function in function_stats:
        if function[1]/elapsed_time > 1:
            frequent_functions.append(function[0])
            print(f"Function {function[0]} was called {function[1]} times in {elapsed_time} seconds")



if __name__ == "__main__":
    main()
