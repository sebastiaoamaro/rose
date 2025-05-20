import random
from types import new_class
import yaml
import signal
import sys
import subprocess
from processor.processor import History, choose_faults, compare_faults, write_new_schedule,get_fault_by_name
from processor.binary_parser import calculate_offsets,calculate_plt_offsets,calculate_call_offsets
from parser.conditions import file_syscall_condition, syscall_condition, time_cond, user_function_condition
import shutil
import time
import math
from copy import deepcopy

class BugReproduction:
    def __init__(self):
        self.schedule = ""
        self.oracle = ""
        self.result_folder = ""
        self.trace_location = ""
        self.base_trace = ""
        self.buggy_trace = ""
        self.cleanup = ""
        self.runs = 0
        self.binary = ""
        self.functions_file = ""

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

    if "binary" in bug_reproduction_text:
        bug_reproduction.binary = bug_reproduction_text["binary"]

    if "functions_file" in bug_reproduction_text:
        bug_reproduction.functions_file = bug_reproduction_text["functions_file"]

    if "base_trace" in bug_reproduction_text:
        bug_reproduction.base_trace = bug_reproduction_text["base_trace"]

    return bug_reproduction

def run_reproduction(schedule):
    command = ["sudo","./run_reproduction.sh", schedule]
    try:
        with open("/tmp/run_reproduction.log", 'w', buffering=1) as file:  # Line buffering
            with subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Merge stderr into stdout
                text=True,
                bufsize=1,  # Line buffered
                errors='replace'  # Handle encoding errors
            ) as process:
                # Read output in real-time
                while True:
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break  # Process exited
                        continue  # No output yet but process still running

                    #print(line, end='')  # Optional: show in console
                    file.write(line)

                # Check exit code after process completion
                if process.returncode != 0:
                    raise subprocess.CalledProcessError(
                        process.returncode,
                        command
                    )
    except subprocess.CalledProcessError as e:
        print(f"\nrun_reproduction finished with: exit code {e.returncode}")
        # Consider re-raising or handling differently
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")

def check_oracle(oracle,run,result_folder):
    command = ["sudo",oracle, run, result_folder]

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
        #print("Output from collect_history:")
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
        #print("Output from cleanup:")
        #print(result.stdout)  # Standard output
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
    trace_location = ""
    if len(bug_reproduction.base_trace) == 0:
        print("Running faultless schedule")
        run_reproduction(bug_reproduction.schedule)
        trace_location = collect_history(bug_reproduction.trace_location,bug_reproduction.result_folder,"normal")
        run_cleanup(bug_reproduction.cleanup)
    else:
        trace_location = bug_reproduction.base_trace

    #Parse faultless schedule
    print("Parsing faultless schedule located at " + trace_location)
    history = History()
    history.parse_schedule(bug_reproduction.schedule)
    history.process_history(trace_location)
    faults_normal = history.discover_faults(None)

    #Parse buggy trace
    print("Parsing buggy trace located at " + bug_reproduction.buggy_trace)
    history_buggy= History()
    history_buggy.parse_schedule(bug_reproduction.schedule)
    history_buggy.process_history(bug_reproduction.buggy_trace)
    faults_buggy = history_buggy.discover_faults(history)
    history_buggy.write_to_file("/tmp/parsed_buggy_history.txt")
    faults_detected = compare_faults(faults_buggy,faults_normal)

    print("FAULTS DETECTED:\n",sorted(faults_detected,key=lambda x:x.start_time))

    runs_counter = 1

    #First attempt run a first schedule, based on first level context information
    faults_detected = choose_faults(faults_detected,history_buggy,history)

    print("FAULTS CHOOSEN:\n",faults_detected)

    schedule_location = "temp_sched.yaml"
    buggy_schedules = []
    print("Running Level 1: First Guess")
    buggy_run = run_test(bug_reproduction,faults_detected)

    history = collect_and_parse(bug_reproduction,schedule_location,"first_guess")

    if (buggy_run):
        buggy_schedule = bug_reproduction.result_folder+"buggy_run:"+"first_guess"+".yaml"
        move_file(schedule_location,buggy_schedule)
        (runs,reproduction_rate) = check_reproduction_rate(schedule_location,bug_reproduction)
        runs_counter+=runs;

        if reproduction_rate >= 75:
            end_reproduction(reproduction_rate,runs_counter,schedule_location,start_time)
            return
        schedule = save_schedule(schedule_location,bug_reproduction.result_folder,"first_guess")
        buggy_schedules.append(schedule)

    print("Running Level 2: What happened before?")

    fault_counter = 0
    faults_detected_time_sorted = sorted(faults_detected,key=lambda x:x.start_time)
    #Second attempts run schedules based on second level context information
    reproduction_rate = 0
    functions_to_analyze = 0

    time_first_fault = faults_detected_time_sorted[0].start_time
    time_rounded_first_fault = math.floor(time_first_fault /10) * 10

    #Holds the last correct history (preserves fault order and condition order)
    last_history = history
    for fault in faults_detected:

        #Ignore faults created by us, temporary remove after refactor
        if "extra" in fault.name: continue

        print("CONTEXTUALIZING FAULT: \n{}".format(fault))
        fault_occuring = True
        condition_order = True
        fault_order = True
        first_buggy_schedule_for_fault = True
        if fault.type == "syscall" and functions_to_analyze == 0:
            call_count = 1
            while reproduction_rate < 75 and fault_occuring:
                call_count+=1
                fault.begin_conditions[0].call_count = call_count
                buggy_run = run_test(bug_reproduction,faults_detected)
                runs_counter+=1
                if buggy_run:
                    (runs,reproduction_rate) = check_reproduction_rate(schedule_location,bug_reproduction)
                    runs_counter+=runs
                    if reproduction_rate >= 75: break
                    run_name = str(fault_counter)+":"+str(call_count)
                    schedule = save_schedule(schedule_location,bug_reproduction.result_folder,run_name)
                    buggy_schedules.append(schedule)
                else:
                    history = collect_and_parse(bug_reproduction,schedule_location,str(call_count))
                    if len(history.faults_injected) == 0: fault_occuring = False
                    for fault_injected_event in history.faults_injected:
                        if fault.name in fault_injected_event.name: fault_occuring = True
                        else: fault_occuring = False
                    if not fault_occuring: fault_counter += 1
            if reproduction_rate > 75: end_reproduction(reproduction_rate,runs_counter,schedule_location,start_time)

        if fault.type in ("process_kill", "process_pause", "block_ips"):
            amplification = 0
            count = 1
            last_event_counter_value = 0
            previous_number_unique_events = -1
            last_used_conditions = deepcopy(fault.begin_conditions)
            last_created_aux_faults = []
            while reproduction_rate < 75 and fault_occuring and condition_order and fault_order and len(last_used_conditions) < 7:
                functions_before = []
                window = 1*count
                if amplification == 0:
                    functions_before = history_buggy.get_functions_before(fault.target,fault.event_id,window)
                    #If we saw all functions before a fault
                    if last_event_counter_value == functions_before[0]:
                        print("Incremented fault_counter saw all functions, LECV:", last_event_counter_value,"FUNC_BEFORE",functions_before[0])
                        fault_counter += 1
                        if previous_number_unique_events > 0: functions_to_analyze += 1
                        break
                    #If incrementing the window did not increase the number of unique functions
                    elif len(functions_before[1]) <= previous_number_unique_events:
                        print("Unique events did not change, or is smaller than previous, or chain_max_size")
                        fault_counter += 1
                        if previous_number_unique_events > 0: functions_to_analyze += 1
                        break;
                    #If there are no unique functions
                    elif len(functions_before[1]) == 0:
                        last_event_counter_value = functions_before[0]
                        previous_number_unique_events = len(functions_before[1])
                        continue;
                    else:
                        last_event_counter_value = functions_before[0]
                        previous_number_unique_events = len(functions_before[1])
                else:
                    functions_before = history_buggy.get_functions_before(fault.target,fault.event_id,window)

                print("USING CHAIN:{}\n".format(functions_before))
                #Add functions to Fault
                fault.begin_conditions = build_fault_conditions(fault,functions_before,history_buggy)
                #Add time condition to Fault
                cond = time_cond()
                time_rounded = 0
                current_index = faults_detected_time_sorted.index(fault)
                fault_before = None
                for prev_index in range(current_index - 1, -1, -1):
                    prev_fault = faults_detected_time_sorted[prev_index]
                    if "syscall" not in prev_fault.name:
                        fault_before = prev_fault
                        break
                #If there is no fault (first_one) we leverage symbols
                if fault_before is None:
                    print("No previous fault ")
                    time_rounded = 0
                else:
                    time_rounded = get_time_for_fault(fault,faults_detected_time_sorted,fault_before,last_history,time_rounded_first_fault)
                if time_rounded != 0:
                    cond.time = time_rounded
                    fault.begin_conditions.append(cond)
                    fault.start_time = time_rounded
                    print("ADDED TIME_COND: ",cond.time)

                #Replicates a state for all faults that share the binary to account for randomness
                faults_created = 1
                faults_to_inject = []
                new_faults = []
                if amplification:
                    new_faults = create_new_faults_for_state(history,fault)
                    faults_created = faults_created+len(new_faults)
                    faults_to_inject = new_faults + faults_detected
                    print("ADDED EXTRA FAULTS")
                else: faults_to_inject = faults_detected

                #Test schedule with new conditions
                run_name = str(fault_counter)+":"+str(count)
                buggy_run = run_test(bug_reproduction,faults_to_inject)
                runs_counter+=1
                if buggy_run and first_buggy_schedule_for_fault:
                    (runs,reproduction_rate) = check_reproduction_rate(schedule_location,bug_reproduction)
                    runs_counter+=runs
                    if reproduction_rate >= 75:
                        break
                    first_buggy_schedule_for_fault = False
                    schedule = save_schedule(schedule_location,bug_reproduction.result_folder,run_name)
                    buggy_schedules.append(schedule)
                elif buggy_run:
                    schedule = save_schedule(schedule_location,bug_reproduction.result_folder,run_name)
                    buggy_schedules.append(schedule)

                #If it is not a buggy_run we need to check if the fault we are changing occurred
                history = collect_and_parse(bug_reproduction,schedule_location,run_name)
                total_faults = 0
                fault_occuring = next((True for x in history.faults_injected if fault.name in x.name), False)

                print("FAULT OCCURRED: ",fault_occuring)
                fault_order = True
                if not fault_occuring:
                    if amplification:
                        #No fault occured after amplification
                        continue;
                    else:
                        fault_occuring=True
                        amplification=1
                        print("FAULT_OCCURING:{},CONDITION_ORDER:{},FAULT_ORDER:{},LEN_LUC:{}".format(fault_occuring,condition_order,fault_order,len(last_used_conditions)))
                        continue

                elif not amplification:
                    fault_order = compare_fault_order(faults_detected_time_sorted,history.faults_injected)

                if not fault_order and not amplification:
                    fault_counter += 1
                    fault.begin_conditions = deepcopy(last_used_conditions)
                    functions_to_analyze += 1
                    continue

                #increment window multiplier
                count+=1
                for fault_injected_event in history.faults_injected:
                    if fault.name in fault_injected_event.name:
                        #print("LUC",last_used_conditions)
                        fault_cond_order = history.check_order(fault_injected_event,window,functions_before[2])

                        #If a previous amplified is out of order then this chain is not good
                        if fault_cond_order and condition_order:
                            condition_order = True
                        else:
                            condition_order = False

                        print("CONDITION ORDER:",condition_order)
                        if not condition_order:
                            fault.begin_conditions = deepcopy(last_used_conditions)
                        else:
                            last_used_conditions = deepcopy(fault.begin_conditions)
                            last_history = history
                        total_faults+=1
                        last_created_aux_faults = new_faults
                #If the faults we created were all called then it is not a random sequence
                print("TOTAL FAULTS:",total_faults)
                print("FAULTS CREATED:",faults_created)
                #If fault did not occur and we did notry amplification it is time to try it
                if amplification:
                    #If we amplified and fault_occured we have to keep doing
                    amplification = total_faults != faults_created
                if not condition_order:
                    fault_counter += 1
                    fault.begin_conditions = deepcopy(last_used_conditions)
                    functions_to_analyze += 1
                    for fault in last_created_aux_faults:
                        fault.begin_conditions = deepcopy(last_used_conditions)
                        faults_detected.append(fault)

        if reproduction_rate > 75:
            end_reproduction(reproduction_rate,runs_counter,schedule_location,start_time)
            return

    schedule_location = write_new_schedule(bug_reproduction.schedule,faults_detected)
    #Thrid attempts run schedules based on third level context information
    if not bug_reproduction.binary == "":
        print("Running Level 3.1: Not all Offsets are Equal: plt")
        for fault in reversed(faults_detected):
            if "extra" in fault.name:
                continue
            #No bugs we reproduce need this
            if fault.type == "syscall":
                continue
            if fault.type in ("process_kill", "process_pause", "block_ips"):
                for cond in fault.begin_conditions:
                    if isinstance(cond, user_function_condition):
                        offsets = calculate_plt_offsets(bug_reproduction.binary, cond.symbol)
                        print("Fault: {}, Offsets for 3.1 are: {}".format(fault.name,offsets))
                        (runs,reproduction_rate,buggy_schedules_3_1) = test_offsets_for_fault(offsets,faults_detected,fault,bug_reproduction,runs_counter,schedule_location,cond)
                        if reproduction_rate > 75:
                            runs_counter+=runs
                            end_reproduction(reproduction_rate,runs_counter,schedule_location,start_time)
                            return
                        for buggy_schedule in buggy_schedules_3_1:
                            buggy_schedules.append(buggy_schedule)
                        #Reset offsets back to 0
                        reset_offset_for_fault(faults_detected,fault,cond)
                        break;

        print("Running Level 3.2: Not all Offsets are Equal: calls")
        for fault in reversed(faults_detected):
            if "extra" in fault.name:
                continue
            #No bugs we reproduce need this
            if fault.type == "syscall":
                continue
            if fault.type in ("process_kill", "process_pause", "block_ips"):
                for cond in fault.begin_conditions:
                    if isinstance(cond, user_function_condition):
                        offsets = calculate_call_offsets(bug_reproduction.binary, cond.symbol)
                        print("Fault: {}, Offsets for 3.2 are: {}".format(fault.name,offsets))
                        (runs,reproduction_rate,buggy_schedules_3_2) = test_offsets_for_fault(offsets,faults_detected,fault,bug_reproduction,runs_counter,schedule_location,cond)
                        if reproduction_rate > 75:
                            runs_counter+=runs
                            end_reproduction(reproduction_rate,runs_counter,schedule_location,start_time)
                            return
                        for buggy_schedule in buggy_schedules_3_2:
                            buggy_schedules.append(buggy_schedule)
                        #Reset offsets back to 0
                        reset_offset_for_fault(faults_detected,fault,cond)
                        break;

        print("Running Level 3.3: Not all Offsets are Equal: all")
        for fault in reversed(faults_detected):
            if "extra" in fault.name:
                continue
            #No bugs we reproduce need this
            if fault.type == "syscall":
                continue
            if fault.type in ("process_kill", "process_pause", "block_ips"):
                for cond in fault.begin_conditions:
                    if isinstance(cond, user_function_condition):
                        offsets = calculate_offsets(bug_reproduction.binary, cond.symbol)
                        print("Fault: {}, Offsets for 3.3 are: {}".format(fault.name,offsets))
                        (runs,reproduction_rate,buggy_schedules_3_3) = test_offsets_for_fault(offsets,faults_detected,fault,bug_reproduction,runs_counter,schedule_location,cond)
                        if reproduction_rate > 75:
                            runs_counter+=runs
                            end_reproduction(reproduction_rate,runs_counter,schedule_location,start_time)
                            return
                        for buggy_schedule in buggy_schedules_3_3:
                            buggy_schedules.append(buggy_schedule)
                        #Reset offsets back to 0
                        reset_offset_for_fault(faults_detected,fault,cond)
                        break;
    best_rr_rate = 0
    best_schedule = ""
    for buggy_schedule in reversed(buggy_schedules):
        runs_counter+=10
        reproduction_rate = check_reproduction_rate_post_phase(buggy_schedule,bug_reproduction)
        if reproduction_rate >= 75:
            end_reproduction(reproduction_rate,runs_counter,buggy_schedule,start_time)
            return
        if reproduction_rate > best_rr_rate:
            best_rr_rate = reproduction_rate
            best_schedule = buggy_schedule
    end_reproduction(reproduction_rate,runs_counter,best_schedule,start_time)

def run_test(bug_reproduction,faults_detected,):
    schedule_location = write_new_schedule(bug_reproduction.schedule,faults_detected)
    run_reproduction(schedule_location)
    buggy_run = check_oracle(bug_reproduction.oracle,str(0),bug_reproduction.result_folder)
    run_cleanup(bug_reproduction.cleanup)
    return buggy_run

def collect_and_parse(bug_reproduction,schedule_location,name):
    history_location = collect_history(bug_reproduction.trace_location,bug_reproduction.result_folder,name)
    history = History()
    history.parse_schedule(schedule_location)
    history.process_history(history_location)
    return history

def check_reproduction_rate(schedule,bug_reproduction):
    print("SCHEDULE:",schedule,"TESTING REPLAY RATE")
    buggy_runs_counter = 0
    normal_runs_counter = 0
    for i in range(0,10):
        run_reproduction(schedule)
        buggy_run = check_oracle(bug_reproduction.oracle,str(0),bug_reproduction.result_folder)
        run_cleanup(bug_reproduction.cleanup)
        if(buggy_run):
            buggy_runs_counter += 1
        else:
            normal_runs_counter+=1
        if normal_runs_counter == 3:
            print("CAN NOT HAVE RR SUPERIOR TO 70%")
            return (buggy_runs_counter+normal_runs_counter, 0)
    reproduction_rate = (buggy_runs_counter*100)/10
    print("RR:",reproduction_rate)
    return (buggy_runs_counter+normal_runs_counter, reproduction_rate)

def check_reproduction_rate_post_phase(schedule,bug_reproduction):
    print("SCHEDULE:",schedule,"TESTING REPLAY RATE")
    buggy_runs_counter = 0
    normal_runs_counter = 0
    for i in range(0,10):
        run_reproduction(schedule)
        buggy_run = check_oracle(bug_reproduction.oracle,str(0),bug_reproduction.result_folder)
        run_cleanup(bug_reproduction.cleanup)
        if(buggy_run):
            buggy_runs_counter += 1
    reproduction_rate = (buggy_runs_counter*100)/10
    print("RR:",reproduction_rate)
    return reproduction_rate

def save_schedule(schedule_location,result_folder,run_name):
    location = result_folder+run_name+".yaml"
    command = ["sudo","cp",schedule_location,location]
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,  # Capture stdout and stderr
            text=True,           # Decode output as text
            check=True           # Raise exception on non-zero exit code
        )
        #print("Output from collect_history:")
        #print(result.stdout)  # Standard output
    except subprocess.CalledProcessError as e:
        print("An error occurred:")
        print(e.stderr)  # Standard error

    return location
def end_reproduction(reproduction_rate,runs,schedule,start_time):
    end_time = time.time()
    elapsed_time = end_time - start_time
    print("RR:",reproduction_rate,"RUNS:",runs,"TIME:",elapsed_time,"SCHEDULE:",schedule)


#Creates the conditions based on faults for a specific fault
def build_fault_conditions(fault,functions_before,history_buggy):
    begin_conditions = []
    for function_call,counter in functions_before[1].items():
        cond = user_function_condition()
        cond.binary_location = history_buggy.nodes[fault.target].binary
        cond.symbol = function_call
        cond.call_count = counter
        begin_conditions.append(cond)
    return begin_conditions

#Calculate the time it should use based on the previous fault
def get_time_for_fault(fault,faults_detected_time_sorted,fault_before,history,time_rounded_first_fault):
    time_fault_current = fault.start_time
    time_rounded_current = math.floor(time_fault_current / 10) * 10
    time_fault_before = get_fault_by_name(faults_detected_time_sorted,fault_before.name).start_time
    time_rounded_before = math.floor(time_fault_before / 10) * 10

    #If the previous fault did not occur in the last attempt we leverage the time before in the original
    #as we did for the previous fault
    fault_before_testing = next((x for x in history.faults_injected if fault_before.name in x.name), None)
    #print("Faults injected in last history:\n",history.faults_injected)
    if fault_before_testing is None:
        print("Time is time of fault {} in original".format(fault_before.name))
        time_rounded = time_rounded_before
    else:
        print("Time is time of fault {} in most recent history".format(fault_before_testing.name))
        #Relax time
        ts = fault_before_testing.relative_time - 1000
        time_rounded = math.floor((ts/1000000) /10) * 10

    if time_rounded <= 0:
        print("Time in testing is sub 0, leverage a default 100 milli value")
        time_rounded = 100
    return time_rounded

def compare_fault_order(faults_detected,faults_injected):
    count_faults = 0
    for fault_detected in faults_detected:
        for fault_injected in faults_injected:
            if fault_detected.name in fault_injected.name:
                count_faults+=1
                break

    all_faults_were_injected = count_faults == len(faults_detected)
    print("Count_faults:{} and faults_detected:{}".format(count_faults,len(faults_detected)))
    if not all_faults_were_injected: return all_faults_were_injected

    fault_names_detected = [f.name for f in faults_detected if "syscall" not in f.name and "extra" not in f.name]
    fault_names_injected = [f.name for f in faults_injected if "syscall" not in f.name and "extra" not in f.name]

    print("fault_names_detected: {}\n".format(fault_names_detected))
    print("fault_names_injected: {}\n".format(fault_names_injected))
    for (i,fault_detected) in enumerate(fault_names_detected):
            fault_detected_prod_time = next((x.start_time for x in faults_detected if x.name == fault_detected), None)
            fault_injected_prod_time = next((x.start_time for x in faults_detected if x.name == fault_names_injected[i]), None)
            gap = abs(fault_detected_prod_time - fault_injected_prod_time)
            print("Checking fault {}, injected {}, gap is {} ".format(fault_detected,fault_names_injected[i],gap))
            if fault_names_injected[i] == fault_detected:
                continue
            elif gap > 2000:
                return False

    return True
#Receives a history and a fault, and creates new_faults with the same state on
#nodes which have the same binary
def create_new_faults_for_state(history,fault):
    new_faults = []
    for node_name,node in history.nodes.items():
        if history.nodes[fault.target].binary == node.binary and fault.target != node_name:
            new_fault = deepcopy(fault)
            new_fault.name = new_fault.name + node_name + "extra"
            new_fault.target = node_name
            new_fault.traced = node_name
            new_faults.append(new_fault)
    return new_faults

def test_offsets_for_fault(offsets,faults_detected,fault,bug_reproduction,runs_counter,schedule_location,cond):
    buggy_schedules = []
    for offset in offsets:
        #Change offsets of faults
        for fault_extra in faults_detected:
            if fault.name in fault_extra.name:
                for i in range(0,len(fault_extra.begin_conditions)):
                    if isinstance(fault_extra.begin_conditions[i], user_function_condition) and fault_extra.begin_conditions[i].symbol == cond.symbol:
                        fault_extra.begin_conditions[i].offset = offset
        buggy_run = run_test(bug_reproduction,faults_detected)
        runs_counter+=1
        if buggy_run:
            run_name = fault.name + str(offset)
            schedule = save_schedule(schedule_location,bug_reproduction.result_folder,run_name)
            buggy_schedules.append(schedule)
            (runs,reproduction_rate) = check_reproduction_rate(schedule_location,bug_reproduction)
            runs_counter+=runs
            if reproduction_rate >= 75:
                return (runs_counter,reproduction_rate,buggy_schedules)
    return (runs_counter,0,buggy_schedules)

def reset_offset_for_fault(faults_detected,fault,cond):
    for fault_extra in faults_detected:
        if fault.name in fault_extra.name:
            for i in range(0,len(fault_extra.begin_conditions)):
                if isinstance(fault_extra.begin_conditions[i], user_function_condition) and fault_extra.begin_conditions[i].symbol == cond.symbol:
                    fault_extra.begin_conditions[i].offset = 0
if __name__ == "__main__":
    main()
