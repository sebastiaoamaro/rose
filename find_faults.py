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

def main():
    filename = sys.argv[1]
    bug_reproduction = parse_bug_reproduction(filename)
    #Run faultless schedule
    print("Running faultless schedule")
    run_reproduction(bug_reproduction.schedule)
    trace_location = collect_history(bug_reproduction.trace_location,bug_reproduction.result_folder,"normal")
    run_cleanup(bug_reproduction.cleanup)

    start_time = time.time()
    #Parse faultless schedule
    print("Parsing faultless schedule located at " + trace_location)
    history = History()
    history.parse_schedule(bug_reproduction.schedule)
    history.process_history(trace_location)
    history.get_events_by_node()
    faults_normal = history.discover_faults()
    run = Run(trace_location,history)

    #Parse buggy trace
    print("Parsing buggy trace located at " + bug_reproduction.buggy_trace)
    history_buggy= History()
    history_buggy.parse_schedule(bug_reproduction.schedule)
    history_buggy.process_history(bug_reproduction.buggy_trace)
    faults_buggy = history_buggy.discover_faults()

    faults_detected = compare_faults(faults_buggy,faults_normal)

    print(faults_detected)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print("TIME:",elapsed_time)

if __name__ == "__main__":
    main()
