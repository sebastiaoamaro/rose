import random
import yaml
import sys
import subprocess
from processor.processor import History, compare_faults, write_new_schedule

class BugReproduction:
    def __init__(self):
        self.schedule = ""
        self.oracled = ""
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
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,  # Capture stdout and stderr
            text=True,           # Decode output as text
            check=True           # Raise exception on non-zero exit code
        )
        #print("Output from schedule:")
        #print(result.stdout)  # Standard output
        #print(result.stderr)
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
        print(result.stdout)  # Standard output
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

#TODO: create compile script and function so that we do not have to compile every time
def main():
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


    faults = compare_faults(faults_buggy,faults_normal)
    #faults_flattened = [item for sublist in faults.values() for item in sublist]
    less_common_faults = min(faults, key=lambda k: len(faults[k]))



    buggy_runs = []
    for i in range(0,30):
        for fault in faults[less_common_faults]:
            fault.start_time = fault.start_time + random.randint(-100, 100)
        new_schedule_location = write_new_schedule(bug_reproduction.schedule,faults[less_common_faults])
        print("In run: " + str(i))
        run_reproduction(new_schedule_location)
        buggy_run = check_oracle(bug_reproduction.oracle,str(i),bug_reproduction.result_folder)
        if (buggy_run):
            print("Buggy run found")
            break
        collect_history(bug_reproduction.trace_location,bug_reproduction.result_folder,str(i))
        run_cleanup(bug_reproduction.cleanup)

    print("Buggy runs: " + str(buggy_runs))
    #Test new_schedule

    # buggy_runs = []
    # for i in range(bug_reproduction.runs):
    #     print("Started reproduction " + str(i))
    #     run_reproduction(bug_reproduction.schedule)
    #     buggy_run = check_oracle(bug_reproduction.oracle,str(i),bug_reproduction.result_folder)
    #     if (buggy_run):
    #         buggy_runs.append(i)
    #     collect_history(bug_reproduction.trace_location,bug_reproduction.result_folder,str(i))
    #     run_cleanup(bug_reproduction.cleanup)
    
    # print("Buggy runs: " + str(buggy_runs))



if __name__ == "__main__":
    main()