import random
import yaml
import sys
import subprocess
from processor.processor import History, choose_faults, compare_faults, write_new_schedule
import shutil
import time

class BugReproduction:
    def __init__(self):
        self.schedule = ""
        self.oracle = ""
        self.result_folder = ""
        self.trace_location = ""
        self.buggy_trace = ""
        self.cleanup = ""
        self.runs = 0

class Run:
    def __init__(self,trace_location,history):
        self.trace_location = trace_location
        self.history = history

def parse_bug_reproduction(filename):
    file = open(filename,"r")

    bug_reproduction_text = yaml.safe_load(file)

    bug_reproduction_text = bug_reproduction_text["reproduction"]

    bug_reproduction = BugReproduction()

    if "schedule" in bug_reproduction_text:
        bug_reproduction.schedule = bug_reproduction_text["schedule"]
    else:
        print("No schedule paramater found")

    if "oracle" in bug_reproduction_text:
        bug_reproduction.oracle = bug_reproduction_text["oracle"]
    else:
        print("No oracle paramater found")

    if "result_folder" in bug_reproduction_text:
        bug_reproduction.result_folder = bug_reproduction_text["result_folder"]
    else:
        print("No result_folder paramater found")

    if "trace_location" in bug_reproduction_text:
        bug_reproduction.trace_location = bug_reproduction_text["trace_location"]
    else:
        print("No trace_location paramater found")

    if "buggy_trace" in bug_reproduction_text:
        bug_reproduction.buggy_trace = bug_reproduction_text["buggy_trace"]
    else:
        print("No buggy_trace paramater found")

    if "cleanup" in bug_reproduction_text:
        bug_reproduction.cleanup = bug_reproduction_text["cleanup"]
    else:
        print("No cleanup paramater found")

    if "runs" in bug_reproduction_text:
        bug_reproduction.runs = int(bug_reproduction_text["runs"])
    else:
        print("No runs paramater found")

    return bug_reproduction

def run_reproduction(schedule):
    command = ["sh","run_reproduction.sh", schedule]

    print("Running command: " + str(command))
    with open('/dev/null', 'w') as devnull:
        try:
        # Start the process
            result = subprocess.run(
                command,
                stdout=devnull,
                stderr=devnull, # Capture stdout and stderr
                check=True           # Raise exception on non-zero exit code
            )
        except subprocess.CalledProcessError as e:
            print("An error occurred:")
            print(e.stderr)  # Standard error

def check_oracle(oracle,run,result_folder):
    command = [oracle, run, result_folder]

    buggy_run = False
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,  # Capture stdout and stderr
            text=True,           # Decode output as text
            check=True           # Raise exception on non-zero exit code
        )
        print("Output from oracle:")
        print(result.stdout)  # Standard output

        if(result.stdout != '\n'):
            buggy_run = True
    except subprocess.CalledProcessError as e:
        print("An error occurred:")
        print(e.stderr)  # Standard error

    return buggy_run

def collect_history(trace_location,result_folder,run):

    location = result_folder+run+".txt"
    command = ["sudo","mv",trace_location,location]
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,  # Capture stdout and stderr
            text=True,           # Decode output as text
            check=True           # Raise exception on non-zero exit code
        )
        print("Output from collect_history:")
        #print(result.stdout)  # Standard output
    except subprocess.CalledProcessError as e:
        print("An error occurred:")
        print(e.stderr)  # Standard error

    return location

def run_cleanup(cleanup):
    if len(cleanup) == 0:
        return

    command = ["sh",cleanup]
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,  # Capture stdout and stderr
            text=True,           # Decode output as text
            check=True           # Raise exception on non-zero exit code
        )
        print("Output from cleanup:")
        print(result.stdout)  # Standard output
    except subprocess.CalledProcessError as e:
        print("An error occurred:")
        print(e.stderr)  # Standard error

def move_file(source_path, destination_path):
    try:
        shutil.copy(source_path, destination_path)
        print(f"File moved successfully from {source_path} to {destination_path}")
    except FileNotFoundError:
        print("Error: Source file not found.")
    except PermissionError:
        print("Error: Permission denied.")
    except Exception as e:
        print(f"Error: {e}")

def main():
    start_time = time.time()
    filename = sys.argv[1]

    bug_reproduction = parse_bug_reproduction(filename)

    #Run faultless schedule
    print("Running faultless schedule")
    run_reproduction(bug_reproduction.schedule)
    trace_location = collect_history(bug_reproduction.trace_location,bug_reproduction.result_folder,"normal")
    run_cleanup(bug_reproduction.cleanup)

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

    buggy_runs = []
    buggy_schedules = []
    buggy_schedule = ""
    runs_counter = 1
    #Run the first schedule and see what occurs
    faults_for_schedule = choose_faults(faults_detected,history_buggy,history)

    new_schedule_location = write_new_schedule(bug_reproduction.schedule,faults_for_schedule)
    run_reproduction(new_schedule_location)
    buggy_run = check_oracle(bug_reproduction.oracle,str(0),bug_reproduction.result_folder)
    run_cleanup(bug_reproduction.cleanup)

    if (buggy_run):
        buggy_schedule = bug_reproduction.result_folder+"buggy_run:"+"first_guess"+".yaml"
        move_file(new_schedule_location,buggy_schedule)
        buggy_schedules.append(buggy_schedule)
        reproduction_rate = check_reproduction_rate(new_schedule_location,bug_reproduction)
        runs_counter+=10;

        if reproduction_rate >= 75:
            end_reproduction(reproduction_rate,runs_counter,new_schedule_location,start_time)
            return

    return
    fault_counter = 0
    for fault in faults_for_schedule:
        if fault.type == "syscall":
            call_count = 1
            reproduction_rate = 0
            fault_occuring = True
            while reproduction_rate < 75 and fault_occuring:
                call_count+=1
                fault.begin_conditions[0].call_count = call_count
                new_schedule_location = write_new_schedule(bug_reproduction.schedule,[fault])
                run_reproduction(new_schedule_location)
                buggy_run = check_oracle(bug_reproduction.oracle,str(call_count),bug_reproduction.result_folder)
                run_cleanup(bug_reproduction.cleanup)
                runs_counter+=1
                if buggy_run:
                    reproduction_rate = check_reproduction_rate(new_schedule_location,bug_reproduction)
                    runs_counter+=10
                    if reproduction_rate >= 75:
                        break
                else:
                    #If it is not a buggy_run we need to check if the fault we are changing occurred
                    history_location = collect_history(bug_reproduction.trace_location,bug_reproduction.result_folder,str(call_count))
                    history = History()
                    history.parse_schedule(new_schedule_location)
                    history.process_history(history_location)

                    for fault_injected_event in history.faults_injected:
                        if fault_counter == fault_injected_event.id:
                            fault_ocurring = True
                            break
                        fault_ocurring = False
                        fault_counter += 1

            end_reproduction(reproduction_rate,runs_counter,new_schedule_location,start_time)
            return

def check_reproduction_rate(schedule,bug_reproduction):
    print("Checking if schedule reproduces bug")
    buggy_runs_counter = 0
    for i in range(0,10):
        run_reproduction(schedule)
        buggy_run = check_oracle(bug_reproduction.oracle,str(0),bug_reproduction.result_folder)
        run_cleanup(bug_reproduction.cleanup)
        if(buggy_run):
            buggy_runs_counter += 1

    reproduction_rate = (buggy_runs_counter*100)/10
    print("RR:",reproduction_rate)
    return reproduction_rate


def end_reproduction(reproduction_rate,runs,schedule,start_time):
    end_time = time.time()
    elapsed_time = end_time - start_time
    print("RR:",reproduction_rate,"RUNS:",runs,"TIME:",elapsed_time,"SCHEDULE:",schedule)

if __name__ == "__main__":
    main()
