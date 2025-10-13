import random
import yaml
import signal
import sys
import subprocess
from analyzer.trace_analysis import History, choose_faults, compare_faults, write_new_schedule
from analyzer.binary_parser import calculate_offsets
from schedule_parser.conditions import file_syscall_condition, syscall_condition, time_cond, user_function_condition
import shutil
import time
import math
from copy import deepcopy
import os
from rose import BugReproduction, parse_bug_reproduction,run_reproduction,run_cleanup,collect_history
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

def get_symbols(relevant_files,binary,output_file):
    command = ["profiler/get_symbols_by_keyword.sh", relevant_files,binary,output_file]

    print(command)
    try:
        with open("/tmp/profile.log", 'w', buffering=1) as file:  # Line buffering
            with subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                text=True,
                bufsize=1,
                errors='replace'
            ) as process:
                while True:
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    file.write(line)
                if process.returncode != 0:
                    raise subprocess.CalledProcessError(
                        process.returncode,
                        command
                    )
    except subprocess.CalledProcessError as e:
        print(f"\nrun_reproduction finished with: exit code {e.returncode}")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")

def collect_profile(profile_location):

    command = ["sudo","mv","/tmp/history.txt",profile_location+"faultless_execution.txt"]
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("An error occurred:")
        print(e.stderr)

    command = ["sudo","mv","/tmp/function_stats.txt",profile_location+"function_stats.txt"]
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("An error occurred:")
        print(e.stderr)

    command = ["sudo","mv","/tmp/syscall_stats.txt",profile_location+"syscall_stats.txt"]
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("An error occurred:")
        print(e.stderr)

def main():
    filename = sys.argv[1]
    bug_reproduction = parse_bug_reproduction(filename)
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

    if bug_reproduction.binary != "" and bug_reproduction.functions_file == "":
        get_symbols(bug_reproduction.profile+"relevant_files.txt",bug_reproduction.binary,bug_reproduction.profile+"functions.txt")

        bug_reproduction = parse_bug_reproduction(filename)
        start_time = time.time()
        print("Running faultless schedule")
        run_reproduction(bug_reproduction.schedule)
        run_cleanup(bug_reproduction.cleanup)
        end_time = time.time()
        elapsed_time = end_time - start_time
        failed_probes = parse_file_split_by_comma("/tmp/failed_probes.txt")
        function_stats = parse_file_split_by_comma("/tmp/function_stats.txt")

        frequent_functions = []
        for function in function_stats:
            ratio = int(function[2])/elapsed_time
            if ratio > 2:
                print("Ratio is {}, total calls is {} time_elasped is {}".format(ratio, function[2],elapsed_time))
                frequent_functions.append(function[0])

        #Add probes which we could not attach
        for failed_probe in failed_probes:
            frequent_functions.append(failed_probe[0])


        for frequent_function in frequent_functions:
            #print(f"Removing function {frequent_function}")
            delete_function_from_file(bug_reproduction.profile+"functions.txt", frequent_function)

    collect_profile(bug_reproduction.profile)

if __name__ == "__main__":
    main()
