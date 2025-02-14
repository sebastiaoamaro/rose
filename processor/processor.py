import math
import struct
import sys
import ipaddress
import yaml
import os

import parser.nodes
from parser.faults import Fault, block_ips, syscall
from parser.conditions import file_syscall_condition, syscall_condition, time_cond, user_function_condition
from pathlib import Path

class Event:
    """
    A class representing a single event with attributes: Node, Pid, Tid, name, and time.
    """
    def __init__(self,type, node, pid, tid, name, time,ret,arg1,arg2,arg3,arg4,arg5):
        self.type = type
        self.id = 0
        self.node = node
        self.pid = int(pid)
        self.tid = tid
        self.name = name
        self.time = time
        self.relative_time = 0
        self.ret = ret
        self.nodes = None

        if name == "connect":
            big_endian_bytes = struct.pack('<I', int(arg1))  # Pack as little-endian
            big_endian_int = struct.unpack('>I', big_endian_bytes)[0]  # Unpack as big-endian
            self.arg1 = ipaddress.IPv4Address(big_endian_int)
            self.arg2 = arg2

        elif name == "network_delay" or name == "network_information":
            big_endian_bytes = struct.pack('<I', int(arg1))  # Pack as little-endian
            big_endian_int = struct.unpack('>I', big_endian_bytes)[0]  # Unpack as big-endian
            self.arg1 = ipaddress.IPv4Address(big_endian_int)

            big_endian_bytes = struct.pack('<I', int(arg2))  # Pack as little-endian
            big_endian_int = struct.unpack('>I', big_endian_bytes)[0]  # Unpack as big-endian
            self.arg2 = ipaddress.IPv4Address(big_endian_int)
        else:
            self.arg1 = arg1
            self.arg2 = arg2

        self.arg3 = arg3
        self.arg4 = arg4

        if arg5 == "na":
            self.arg5 = ""
        else:
            self.arg5 = arg5



    def __repr__(self):
        return (f"Event(Node={self.node},Pid={self.pid},Tid={self.tid},Type={self.type},name={self.name}),Id={self.id},Relative_Time={self.format_time_ns()},Ret={self.ret},Arg1={self.arg1},Arg2={self.arg2},Arg3={self.arg3},Arg4={self.arg4},Arg5={self.arg5}\n")

    def format_time_ns(self):
        seconds = self.relative_time // 1_000_000_000
        milliseconds = (self.relative_time % 1_000_000_000) // 1_000_000
        remaining_nanoseconds = self.relative_time % 1_000_000

        return f"{seconds} seconds, {milliseconds} milliseconds, {remaining_nanoseconds} nanoseconds"

    def check_if_fault(self):
        if "Fault" in self.name:
            return True
        if self.name == "network_delay":
            return True
        if self.name == "process_change":
            return True
        if self.name == "Start":
            return True
        if self.name == "End":
            return True

class History:
    """
    A class responsible for reading and parsing events from a file.
    The events are stored in a dictionary organized by node.
    """
    def __init__(self):
        self.events = []
        self.events_by_node = {}
        self.pids = {}
        self.ids = {}
        self.new_pid_events = {}
        self.event_counter = {}
        self.start_time = 0
        self.end_time = -1
        self.faults = []
        self.network_history = {}
        self.ip_to_node = {}
        self.experiment_time = 0
        self.faults_injected = []
        self.function_calls_by_node = {}


    def parse_event_line(self, line):
        """
        Parses a single line of the event log and returns an Event object.

        Example line format: "Node:{},Pid:{},Tid:{},Function:{},time:{} \n"
        """
        # Strip any extra whitespace and newlines
        line = line.strip()

        # Split the line into its components based on the format
        event_data = {}
        parts = line.split(',')

        for part in parts:
            key, value = part.split(':', 1)
            event_data[key] = value

        # Create an Event object using the parsed data

        #First event we see
        if self.start_time == 0:
            self.start_time = int(event_data['time'])

        if self.start_time > int(event_data['time']):
            self.start_time = int(event_data['time'])

        if self.end_time < int(event_data['time']):
            self.end_time = int(event_data['time'])

        return Event(
            type=event_data['event_type'],
            node=event_data['Node'],
            pid=event_data['Pid'],
            tid=event_data['Tid'],
            name=event_data['event_name'],
            time= int(event_data['time']),
            ret=event_data['ret'],
            arg1=event_data['arg1'],
            arg2=event_data['arg2'],
            arg3=event_data['arg3'],
            arg4=event_data['arg4'],
            arg5=event_data['arg5']
        )

    def read_and_parse_events(self, file_path):
        """
        Reads the event file and creates a dictionary of events per node.

        :param file_path: Path to the file to read.
        :return: Dictionary with node IDs as keys and a list of Event objects as values.
        """
        # Open the file and read line by line
        with open(file_path, 'r') as file:
            for line in file:
                # Parse the current line to extract the event
                event = self.parse_event_line(line)

                # Get the node ID for the current event
                node_id = event.node

                # If the node doesn't exist in the dictionary, initialize a list
                if node_id not in self.events_by_node:
                    self.events_by_node[node_id] = []
                if node_id not in self.function_calls_by_node:
                    self.function_calls_by_node[node_id] = {}

                # Append the event to the list for the corresponding node
                self.events.append(event)

                if event.type == "Fault":
                    self.faults_injected.append(event)

                if event.type == "function_call":
                    if event.name not in self.function_calls_by_node[node_id]:
                        self.function_calls_by_node[node_id][event.name] = [event]
                    else:
                        self.function_calls_by_node[node_id][event.name].append(event)
                if event.type in self.event_counter:
                    self.event_counter[event.name].append(event)
                else:
                    self.event_counter[event.name] = [event]

    def get_events_by_node(self):
        for event in self.events:
            node_id = event.node
            self.events_by_node[node_id].append(event)

            if node_id not in self.ids:
                self.ids[node_id] = 0
            else:
                self.ids[node_id]+= 1

            event.id = self.ids[node_id]

            if node_id not in self.pids:
                self.pids[node_id] = []
                self.new_pid_events[node_id] = []

            if event.pid not in self.pids[node_id] and int(event.pid) !=0 and int(event.pid) !=4:
                self.pids[node_id].append(event.pid)
                self.new_pid_events[node_id].append(event)


    def count_sys_exit_errors(self):
        self.sys_exit_errors = {}
        for event in self.events:
            if event.type == "sys_exit":
                if event.name in self.sys_exit_errors:
                    self.sys_exit_errors[event.name]+=1
                else:
                    self.sys_exit_errors[event.name]=1


    def order_events(self):
        for node_id in self.events_by_node:
            self.events_by_node[node_id].sort(key=lambda x: x.time)

        self.events.sort(key=lambda x: x.time)

        for event in self.events:
            event.relative_time = event.time - self.start_time

    def process_history(self,history_file):
        self.read_and_parse_events(history_file)
        self.count_sys_exit_errors()
        self.get_events_by_node()
        self.order_events()
        self.experiment_time = (self.end_time - self.start_time)/1000000000

    def parse_schedule(self,schedule_file):
        file = open(schedule_file,"r")
        schedule = yaml.safe_load(file)
        self.nodes = parser.nodes.parse_nodes(schedule['nodes'])

        for node_name,node in self.nodes.items():
            self.network_history[node_name] = {}
            for node_dest in self.nodes:
                self.network_history[node_name][node_dest] = []
            self.ip_to_node[str(node.ip)] = node_name


    def discover_faults(self):

        self.get_events_by_node()

        fault_nr = 0
        for event in self.events:
            if event.type == "network_event":
                ip_src = event.arg1
                ip_dst = event.arg2
                for key,node in self.nodes.items():
                    if str(node.ip) == str(ip_src):
                        event.node = node.name

                if (event.node == "any"):
                    continue

                dest_node = 0
                try:
                    dest_node = self.ip_to_node[str(ip_dst)]
                except:
                    continue

                start = event.time - int(event.arg3)*1000000
                #Network event has frequency, delay, start_time,end_time,id
                network_event = (int(event.arg4),int(event.arg3),start,event.time,event.id)

                self.network_history[event.node][dest_node].append(network_event)


            if event.type == "network_information":
                ip_src = event.arg1
                ip_dst = event.arg2
                for node_name,node in self.nodes.items():
                    if str(node.ip) == str(ip_src):
                        event.node = node.name

                if (event.node == "any"):
                        continue

                dest_node = 0
                try:
                    dest_node = self.ip_to_node[str(ip_dst)]
                except:
                    continue

                #Skip IPs not in experiment
                if dest_node == 0:
                    continue

                #Skip packets to itself
                if event.node == dest_node:
                    continue

                frequency = event.arg3
                if int(frequency)/(self.experiment_time) > 1:
                    delay = int((self.end_time-event.time)/1000000)
                    #If delay is less than 250, then it is not relevant
                    if delay < 5000:
                        continue
                    #Network event has frequency, delay, start_time,end_time,id
                    network_event = (int(event.arg3),delay,event.time,self.end_time,event.id)

                    self.network_history[event.node][dest_node].append(network_event)


            if event.type == "process_state_change":
                for node_name,pid_list in self.pids.items():
                    if event.pid in pid_list:
                        event.node = node_name

            #Process sycall Fault
            if event.type == "sys_exit":

                fault = Fault()
                fault.name = "syscall" + str(fault_nr)
                fault.fault_category = 2
                fault.type = "syscall"

                fault_specifics = syscall()
                fault_specifics.syscall_name = event.name
                fault_specifics.return_value = event.ret
                fault.start_time = event.relative_time/1000000
                fault.fault_specifics = fault_specifics

                fault.target = event.node
                fault.traced = event.node

                fault.begin_conditions = []

                #Check if the syscall has a filename
                if len(event.arg5)>0:
                    cond = file_syscall_condition()

                    #cond.time = event.relative_time/1000000
                    cond.syscall_name = event.name
                    cond.file_name = get_name_from_path(event.arg5)
                    cond.call_count = 1
                    fault.begin_conditions.append(cond)

                    fault_nr += 1
                    fault.state_score = 2
                #If it does not try to leverage the counter only
                elif len(self.event_counter[event.name]) < 100:
                    cond = syscall_condition()
                    cond.syscall_name = event.name
                    cond.call_count = 1
                    fault.begin_conditions.append(cond)

                    fault_nr += 1
                    fault.state_score = 1

                #TODO: look for syscalls before which have context
                else:
                    cond = file_syscall_condition()
                    last_syscall_event = self.get_context_syscall_before(event.node,event.id)
                    cond.syscall_name = last_syscall_event.name
                    cond.file_name = get_name_from_path(event.arg5)
                    cond.call_count = 1
                    fault.begin_conditions.append(cond)

                    fault_nr += 1
                    fault.state_score = 1

                self.faults.append(fault)

            #Find process pauses/waits
            if event.type == "process_state_change":
                print("Found process pause creating fault")
                fault = Fault()
                fault.name = "process_pause" + str(fault_nr)
                fault.fault_category = 0
                fault.type = "process_pause"
                fault.state_score = 3

                fault.target = event.node
                fault.traced = event.node
                fault.duration = int(event.arg2)*1000

                fault.begin_conditions = []

                #TODO: Move this block of code to function: find_state_of_fault
                functions_before = self.get_functions_before(event.node,event.id)

                for function_call,counter in functions_before.items():
                    cond = user_function_condition()
                    cond.binary_location = self.nodes[event.node].binary
                    cond.symbol = function_call
                    cond.call_count = counter
                    fault.begin_conditions.append(cond)
                    fault.state_score += len(fault.begin_conditions)


                if len(fault.begin_conditions) == 0:
                    cond = time_cond()
                    cond.time = int((event.relative_time)/1000000)
                    cond.time = math.floor(cond.time / 10000) * 10000
                    fault.start_time = cond.time
                    fault.begin_conditions.append(cond)

                fault_nr += 1
                self.faults.append(fault)


        #Find network faults
        for node in self.nodes:
            for dest_node,list in self.network_history[node].items():
                for event in list:
                    if event[2] < self.start_time:
                        print("Network event before start time")
                        continue
                    if event[0]/self.experiment_time < 1:
                        #print("Frequency too low" + " time: " + str(self.experiment_time) + " count: " + str(event[0]) )
                        continue

                    fault = Fault()
                    fault.name = "networkfault" + str(fault_nr)
                    fault.fault_category = 0
                    fault.type = "block_ips"
                    fault.state_score = 3

                    #Blocking both ways for simplicity now
                    fault_specifics = block_ips()
                    print("Dest node is " + dest_node)
                    fault_specifics.nodes_in = [dest_node]
                    fault_specifics.nodes_out = [dest_node]
                    fault.fault_specifics = fault_specifics

                    fault.target = node
                    fault.traced = node
                    fault.duration = event[1]

                    fault.begin_conditions = []

                    functions_before = self.get_functions_before(node,event[4])

                    for function_call,counter in functions_before.items():
                        cond = user_function_condition()
                        cond.binary_location = self.nodes[node].binary
                        cond.symbol = function_call
                        cond.call_count = counter
                        fault.begin_conditions.append(cond)
                        fault.state_score += len(fault.begin_conditions)

                    if len(fault.begin_conditions) == 0:
                        cond = time_cond()
                        cond.time = int((event[2]-self.start_time)/1000000)
                        cond.time = math.floor(cond.time / 10000) * 10000
                        fault.start_time = cond.time
                        fault.begin_conditions.append(cond)
                    fault_nr += 1
                    self.faults.append(fault)

        #Find process crashes
        for node,pids in self.pids.items():
            if node == "any":
                continue
            if len(pids) > 1:
                for i in range(1,len(pids)):
                    fault = Fault()
                    fault.name = "process_kill" + str(fault_nr)
                    fault.fault_category = 1
                    fault.type = "process_kill"
                    fault.target = node
                    fault.traced = node
                    fault.state_score = 3
                    fault.duration = 0
                    #check conditions
                    fault.begin_conditions = []

                    last_event_before_crash = self.find_event_before_id(node,self.new_pid_events[node][i].id)

                    functions_before = self.get_functions_before(node,self.new_pid_events[node][i].id)
                    for function_call,counter in functions_before.items():
                        cond = user_function_condition()

                        cond.binary_location = self.nodes[self.new_pid_events[node][i].node].binary
                        cond.symbol = function_call
                        cond.call_count = counter

                        fault.begin_conditions.append(cond)
                        fault.state_score += len(fault.begin_conditions)

                    if len(fault.begin_conditions) == 0:
                            cond = time_cond()
                            cond.time = int((last_event_before_crash.time - self.start_time)/1000000)
                            cond.time = math.floor(cond.time / 10000) * 10000
                            fault.start_time = cond.time
                            fault.begin_conditions.append(cond)

                    fault_nr += 1
                    self.faults.append(fault)

        return self.faults

    def get_functions_before(self,node_name,event_id):

        function_calls = []
        #This will serve as the conditions for the fault
        function_calls_counter = {}
        event_list = self.events_by_node[node_name]
        event_size_list = 15

        event_counter = 0
        for event in reversed(event_list):
            if event.type == "function_call" and event.id < event_id:
                function_calls.append(event)
                if event.name in function_calls_counter:
                    function_calls_counter[event.name] += 1
                else:
                    function_calls_counter[event.name] = 1

                event_counter+=1
                if event_counter == event_size_list:
                    break

        for function_call in function_calls:
             if function_call.name in function_calls_counter and len(self.function_calls_by_node[node_name][function_call.name]) > 2:
                 function_calls_counter.pop(function_call.name)

        #print(function_calls_counter)
        return function_calls_counter

    def get_context_syscall_before(self,node_name,event_id):
        event_list = self.events_by_node[node_name]

        for event in reversed(event_list):
            if event.type  == "syscall_exit" and event.id < event_id and len(event.arg5) > 0:
                return event

    def find_event_before_id(self,node_name,event_id):
        for event in reversed(self.events_by_node[node_name]):
            if event.id < event_id:
                return event

def write_new_schedule(base_schedule,faults):

    file = open(base_schedule,"r")
    base_schedule = yaml.safe_load(file)

    exe_plan = {"execution_plan": base_schedule["execution_plan"]}
    nodes = {"nodes":base_schedule["nodes"]}

    schedule_location = "temp_sched.yaml"
    with open('temp_sched.yaml', 'w') as file:
        yaml.dump(exe_plan, file, default_flow_style=False)
        yaml.dump(nodes, file, default_flow_style=False)

        faults.sort(key=lambda x: x.start_time)

        faults_dict = {"faults":{}}

        for fault in faults:
            fault_dict = fault.to_yaml()
            faults_dict["faults"][fault.name] = fault_dict
        yaml.dump(faults_dict, file, default_flow_style=False)

    return schedule_location


def compare_faults(buggy_run, normal_run):
    faults_buggy = group_faults(buggy_run)
    faults_normal = group_faults(normal_run)

    unique_faults = set(faults_buggy.keys()) - set(faults_normal.keys())

    faults = []

    for name in unique_faults:
        #futex faults are common
        if "futex" not in name:
            for fault in faults_buggy[name]:
                faults.append(fault)

    return faults

def group_faults(fault_list):

    faults = {}
    for fault in fault_list:
        if fault.type == "syscall":
            if fault.fault_specifics.syscall_name in faults:
                faults[fault.fault_specifics.syscall_name + str(fault.fault_specifics.return_value)].append(fault)
            else:
                faults[fault.fault_specifics.syscall_name + str(fault.fault_specifics.return_value)] = [fault]

        if fault.type == "process_kill":

            if fault.type in faults:
                faults[fault.type].append(fault)
            else:
                faults[fault.type] = [fault]

        if fault.type == "block_ips":
            if fault.type in faults:
                faults[fault.type + fault.target + fault.fault_specifics.nodes_in[0] + str(fault.start_time)].append(fault)
            else:
                faults[fault.type + fault.target + fault.fault_specifics.nodes_in[0] + str(fault.start_time)] = [fault]

        if fault.type == "process_pause":
            if fault.type in faults:
                faults[fault.type + str(fault.target) + str(fault.duration)].append(fault)
            else:
                faults[fault.type + str(fault.target) + str(fault.duration)] = [fault]
    return faults

def get_name_from_path(path):
    return Path(path).name

def choose_faults(faults):
    faults_choosen = []

    partitions = {}
    for fault in faults:
        #Group block_ips to reduce number of total faults
        if fault.type == "block_ips":
            if fault.target + str(fault.start_time) in partitions:
                partitions[fault.target + str(fault.start_time)][0].fault_specifics.nodes_in.append(fault.fault_specifics.nodes_in[0])
                partitions[fault.target + str(fault.start_time)][0].fault_specifics.nodes_out.append(fault.fault_specifics.nodes_out[0])
            else:
                partitions[fault.target + str(fault.start_time)] = [fault]
        if fault.type == "process_kill":
            faults_choosen.append(fault)
        if fault.type == "syscall":
            faults_choosen.append(fault)
        if fault.type =="process_pause":
            faults_choosen.append(fault)

    for partition in partitions:
        faults_choosen.append(partitions[partition][0])

    faults_choosen.sort(key = lambda x: (x.state_score,-x.start_time),reverse=True)

    return faults_choosen[:10]
