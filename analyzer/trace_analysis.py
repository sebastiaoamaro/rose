import ipaddress
import math
import re
import struct
from pathlib import Path

import yaml

import schedule_parser.nodes
from schedule_parser.conditions import (
    file_syscall_condition,
    syscall_condition,
    time_cond,
    user_function_condition,
)
from schedule_parser.faults import Fault, block_ips, check_if_syscall_supported, syscall


class Event:
    """
    A class representing a single event with attributes: Node, Pid, Tid, name, and time.
    """

    def __init__(self, type, node, pid, tid, name, time, ret, arg1, arg2, arg3, arg4, arg5):
        """Stores all event fields; for connect/network events arg1/arg2 are decoded
        from little-endian integers to IPv4Address objects."""
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
            big_endian_bytes = struct.pack("<I", int(arg1))  # Pack as little-endian
            big_endian_int = struct.unpack(">I", big_endian_bytes)[0]
            self.arg1 = ipaddress.IPv4Address(big_endian_int)
            self.arg2 = arg2

        elif name == "network_delay" or name == "network_information":
            big_endian_bytes = struct.pack("<I", int(arg1))  # Pack as little-endian
            big_endian_int = struct.unpack(">I", big_endian_bytes)[0]
            self.arg1 = ipaddress.IPv4Address(big_endian_int)

            big_endian_bytes = struct.pack("<I", int(arg2))  # Pack as little-endian
            big_endian_int = struct.unpack(">I", big_endian_bytes)[0]
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
        """Returns a full string representation of the event including all fields."""
        return f"Event(Node={self.node},Pid={self.pid},Tid={self.tid},Type={self.type},name={self.name}),Id={self.id},Relative_Time={self.format_time_ns()},Ret={self.ret},Arg1={self.arg1},Arg2={self.arg2},Arg3={self.arg3},Arg4={self.arg4},Arg5={self.arg5}\n"

    def format_time_ns(self):
        """Converts relative_time (nanoseconds) into a human-readable seconds / milliseconds / nanoseconds string."""
        seconds = self.relative_time // 1_000_000_000
        milliseconds = (self.relative_time % 1_000_000_000) // 1_000_000
        remaining_nanoseconds = self.relative_time % 1_000_000
        return f"{seconds} seconds, {milliseconds} milliseconds, {remaining_nanoseconds} nanoseconds"


class History:
    """
    Represents a trace.
    """

    def __init__(self):
        """Initializes all data structures: event lists, per-node mappings,
        network history, fault lists, and timing bookmarks."""
        self.nodes = {}
        self.events = []
        self.events_by_node = {}
        # Maps nodes to pid
        self.pids = {}
        self.ids = {}
        self.new_pid_events = {}
        self.event_counter = {}
        self.start_time = 0
        self.start_time_event = False
        self.end_time = -1
        self.faults = []
        self.network_history = {}
        self.network_trace = {}
        self.ip_to_node = {}
        self.experiment_time = 0
        self.faults_injected = []
        self.function_calls_by_node = {}
        self.first_event_id = 0

    def parse_event_line(self, line):
        """Parses a single comma-separated log line into an Event; tracks the global
        start/end timestamps and marks the start event if present. Returns None on error."""
        line = line.strip()
        # Split the line into its components based on the format
        event_data = {}
        parts = line.split(",")
        for part in parts:
            try:
                key, value = part.split(":", 1)
                event_data[key] = value
            except Exception:
                print("Failed to parse part: ", part, " in line: ", line)
                return None
        # First event we see
        if self.start_time == 0 and not self.start_time_event:
            self.start_time = int(event_data["time"])

        if self.start_time > int(event_data["time"]) and not self.start_time_event:
            self.start_time = int(event_data["time"])

        if event_data["event_name"] == "start":
            self.start_time = int(event_data["time"])
            self.start_time_event = True

        if self.end_time < int(event_data["time"]):
            self.end_time = int(event_data["time"])

        return Event(
            type=event_data["event_type"],
            node=event_data["Node"],
            pid=event_data["Pid"],
            tid=event_data["Tid"],
            name=event_data["event_name"],
            time=int(event_data["time"]),
            ret=event_data["ret"],
            arg1=event_data["arg1"],
            arg2=event_data["arg2"],
            arg3=event_data["arg3"],
            arg4=event_data["arg4"],
            arg5=event_data["arg5"],
        )

    def read_and_parse_events(self, file_path):
        """Reads the trace file line by line, populating self.events, self.faults_injected,
        self.function_calls_by_node, and self.event_counter."""
        with open(file_path, "r") as file:
            for line in file:
                event = self.parse_event_line(line)
                if event is None:
                    continue
                node_id = event.node

                # If the node doesn't exist in the dictionary, initialize a list
                if node_id not in self.events_by_node:
                    self.events_by_node[node_id] = []
                if node_id not in self.function_calls_by_node:
                    self.function_calls_by_node[node_id] = {}

                self.events.append(event)

                if event.type == "Fault":
                    self.faults_injected.append(event)

                if event.type == "function_call":
                    if event.name not in self.function_calls_by_node[node_id]:
                        self.function_calls_by_node[node_id][event.name] = [event]
                    else:
                        self.function_calls_by_node[node_id][event.name].append(event)

                if event.name in self.event_counter:
                    self.event_counter[event.name].append(event)
                else:
                    self.event_counter[event.name] = [event]

    def get_events_by_node(self):
        """Groups events into self.events_by_node keyed by node ID, assigns a
        per-node monotonic event.id, tracks observed PIDs per node
        (self.pids / self.new_pid_events), and re-assigns the node of "any"
        events by matching their PID or source IP against known nodes."""
        for event in self.events:
            node_id = event.node
            self.events_by_node[node_id].append(event)

            if node_id == "any" and event.type != "Fault":
                if event.pid != 0:
                    for node_name, pid_list in self.pids.items():
                        if event.pid in pid_list:
                            event.node = node_name
                else:
                    for node_name, node in self.nodes.items():
                        ip_src = event.arg1
                        if str(node.ip) == str(ip_src):
                            event.node = node.name

            if node_id not in self.ids:
                self.ids[node_id] = 0
            else:
                self.ids[node_id] += 1

            event.id = self.ids[node_id]

            if node_id not in self.pids and node_id != "any":
                self.pids[node_id] = []
                self.new_pid_events[node_id] = []

            if node_id != "any" and event.pid not in self.pids[node_id] and int(event.pid) != 0 and int(event.pid) != 4:
                self.pids[node_id].append(event.pid)
                self.new_pid_events[node_id].append(event)

    def order_all_events(self):
        """Sorts all events and injected faults by timestamp, then sets each event's
        relative_time as an offset from self.start_time."""
        self.events.sort(key=lambda x: x.time)
        self.faults_injected.sort(key=lambda x: x.time)
        for event in self.events:
            event.relative_time = event.time - self.start_time
        for fault in self.faults_injected:
            fault.relative_time = fault.time - self.start_time

    def process_history(self, history_file):
        """Full pipeline: reads and parses the trace file, orders events by time,
        groups them by node, and computes self.experiment_time."""
        self.read_and_parse_events(history_file)
        self.order_all_events()
        self.get_events_by_node()
        # Order events_by_node
        for node_id in self.events_by_node:
            self.events_by_node[node_id].sort(key=lambda x: x.time)
        self.experiment_time = (self.end_time - self.start_time) / 1000000000

    def parse_schedule(self, schedule_file):
        """Loads the YAML schedule to populate self.nodes, initializes per-node
        network history buckets, and builds an IP-to-node-name mapping."""
        file = open(schedule_file, "r")
        schedule = yaml.safe_load(file)
        self.nodes = schedule_parser.nodes.parse_nodes(schedule["nodes"])

        for node_name, node in self.nodes.items():
            self.network_history[node_name] = {}
            for node_dest in self.nodes:
                self.network_history[node_name][node_dest] = []
            self.ip_to_node[str(node.ip)] = node_name

    def discover_faults(self, normal_history):
        """Scans all events to detect syscall errors, process kills, process pauses,
        and network isolations; builds a Fault object for each and appends to
        self.faults. Returns the completed fault list."""
        fault_nr = 0
        for event in self.events:
            if event.type == "sys_exit":
                support = self.check_syscall_support(event.name)
                if not support:
                    continue
                syscall_name = event.name
                return_value = event.ret
                fault = Fault()
                fault.name = "syscall" + str(fault_nr)
                fault.fault_category = 2.0
                fault.type = "syscall"
                fault_specifics = syscall()
                fault_specifics.syscall_name = syscall_name
                fault_specifics.return_value = return_value
                fault.start_time = event.relative_time / 1000000
                fault.fault_specifics = fault_specifics
                fault.event_id = event.id
                fault.target = event.node
                fault.traced = event.node
                fault.begin_conditions = []

                # Check if the syscall has a filename
                if len(event.arg5) > 0:
                    cond = file_syscall_condition()
                    # cond.time = event.relative_time/1000000
                    cond.syscall_name = syscall_name
                    cond.file_name = remove_numbers(get_name_from_path(event.arg5))
                    cond.call_count = 1
                    fault.begin_conditions.append(cond)
                    fault.state_score = 1.5
                # If it does not try to leverage the counter only
                elif len(self.event_counter[event.name]) < 150:
                    cond = syscall_condition()
                    cond.syscall_name = syscall_name
                    cond.call_count = 1
                    fault.begin_conditions.append(cond)
                    fault.state_score = 1.0

                    time = int((event.time - self.start_time) / 1000000)
                    time_rounded = math.floor(time / 10) * 10
                    fault.start_time = time_rounded
                # If we can not leverage information from the syscall itself, look for previous ones, this can not be done here takes to much time
                else:
                    continue

                fault_nr += 1
                self.faults.append(fault)
            # Find process crashes
            if event.type == "process_state_change" and event.arg1 == "1":
                for node_name, pid_list in self.pids.items():
                    if event.pid in pid_list:
                        event.node = node_name

                fault = Fault()
                fault.name = "process_kill" + str(fault_nr)
                fault.fault_category = 0
                fault.type = "process_kill"
                fault.state_score = 3
                fault.target = event.node
                fault.traced = event.node
                fault.begin_conditions = []

                events = self.events_by_node[event.node]
                prev_event = None
                for previous_event in reversed(events):
                    if previous_event.time < event.time and previous_event.pid == event.pid:
                        prev_event = previous_event
                        break

                fault.event_id = prev_event.id

                time = int((prev_event.time - self.start_time) / 1000000)
                time_rounded = math.floor(time / 10) * 10
                fault.start_time = time_rounded

                cond = time_cond()
                cond.time = time_rounded
                fault.begin_conditions.append(cond)

                fault_nr += 1
                self.faults.append(fault)

            # Find process pauses/waits
            if event.type == "process_state_change" and event.arg1 == "4":
                for node_name, pid_list in self.pids.items():
                    if event.pid in pid_list:
                        event.node = node_name

                fault = Fault()
                fault.name = "process_pause" + str(fault_nr)
                fault.fault_category = 0
                fault.type = "process_pause"
                fault.state_score = 3
                fault.target = event.node
                fault.traced = event.node
                fault.duration = int(event.arg2) * 1000
                fault.begin_conditions = []

                time = int(((event.time - self.start_time) / 1000000) - fault.duration)
                # We add a pause event after it is finished thus its start is at -duration
                time_rounded = math.floor(time / 10) * 10
                fault.start_time = time_rounded

                # Processes are stopped by us to setup other things, thus pauses at the start are detected but are not real
                if fault.start_time <= 1000:
                    print("Skipped process_pause it is at the start target was {} duration was {}".format(fault.target, fault.duration))
                    continue

                fault_timestamp = int(event.time) - fault.duration * 1000000
                fault.event_id = self.find_event_by_id_by_time(fault_timestamp, event.node)

                cond = time_cond()
                cond.time = time_rounded
                fault.begin_conditions.append(cond)

                fault_nr += 1
                self.faults.append(fault)

            if event.type == "network_event":
                ip_src = event.arg1
                ip_dst = event.arg2
                for key, node in self.nodes.items():
                    if str(node.ip) == str(ip_src):
                        event.node = node.name

                if event.node == "any":
                    # print("Delay between nodes outside of the deployment")
                    continue

                dest_node = 0
                try:
                    dest_node = self.ip_to_node[str(ip_dst)]
                except:
                    # print("No destination node found for network_event")
                    continue

                start = event.time - int(event.arg3) * 1000000
                # Network event has frequency, delay, start_time,end_time,id
                network_event = (int(event.arg4), int(event.arg3), start, event.time, 0)

                self.network_history[event.node][dest_node].append(network_event)

            if event.type == "network_information":
                ip_src = event.arg1
                ip_dst = event.arg2
                for node_name, node in self.nodes.items():
                    if str(node.ip) == str(ip_src):
                        event.node = node.name

                if event.node == "any":
                    # print("Delay between nodes outside of the deployment")
                    continue

                dest_node = 0
                try:
                    dest_node = self.ip_to_node[str(ip_dst)]
                except:
                    continue

                # Skip packets to itself
                if event.node == dest_node:
                    continue

                frequency = event.arg3
                ratio = int(frequency) / (self.experiment_time)
                if ratio > 0.5:
                    # Calculate the delay possible partition which never healed
                    delay = int((self.end_time - event.time) / 1000000)
                    # If delay is less than 5000, then it is not relevant
                    if delay < 5000:
                        continue
                    # Network event has frequency, delay, start_time,end_time,id
                    network_event = (
                        int(event.arg3),
                        delay,
                        event.time,
                        self.end_time,
                        event.id,
                    )

                    self.network_history[event.node][dest_node].append(network_event)

                # Add frequencies to network trace
                if event.node not in self.network_trace:
                    self.network_trace[event.node] = {}

                if dest_node not in self.network_trace[event.node]:
                    self.network_trace[event.node][dest_node] = []

                self.network_trace[event.node][dest_node].append(frequency)

        # Find network faults
        for node in self.nodes:
            for dest_node, list in self.network_history[node].items():
                for event in list:
                    # Network event has frequency, duration, start_time,end_time,id
                    frequency = event[0]
                    duration = event[1]
                    start_time_fault = event[2]
                    end_time = event[3]
                    if start_time_fault < self.start_time:
                        continue
                    if frequency / self.experiment_time < 0.5:
                        continue
                    fault = Fault()
                    fault.name = "networkfault" + str(fault_nr)
                    fault.fault_category = 0
                    fault.type = "block_ips"
                    fault.state_score = 2
                    # Blocking both ways for simplicity now
                    fault_specifics = block_ips()
                    fault_specifics.nodes_in = [dest_node]
                    fault_specifics.nodes_out = [dest_node]
                    fault.fault_specifics = fault_specifics
                    fault.target = node
                    fault.traced = node
                    fault.duration = duration
                    fault.begin_conditions = []
                    time = int((start_time_fault - self.start_time) / 1000000)
                    # Substract duration of fault
                    time_rounded = math.floor(time / 10) * 10
                    fault.start_time = time_rounded

                    fault.event_id = self.find_event_by_id_by_time(start_time_fault, node)

                    if len(fault.begin_conditions) == 0:
                        cond = time_cond()
                        cond.time = time_rounded
                        fault.begin_conditions.append(cond)

                    fault_nr += 1
                    self.faults.append(fault)

        return self.faults

    def get_functions_before(self, node_name, event_id, window):
        """Returns the last `window` function_call events before event_id on node_name,
        plus a count map of calls that appear only once (used to build fault conditions)."""
        function_calls = []
        # This will serve as the conditions for the fault
        function_calls_counter = {}
        event_list = self.events_by_node[node_name]
        event_size_list = window

        event_counter = 0
        for event in reversed(event_list):
            if event.type == "function_call" and event.id < event_id:
                function_calls.append(event)
                if event.name in function_calls_counter:
                    function_calls_counter[event.name] += 1
                else:
                    function_calls_counter[event.name] = 1

                event_counter += 1
                if event_counter == event_size_list:
                    break

        # Checks for unique events in window
        print("Function calls in window:\n", function_calls)
        for function_call in function_calls:
            if function_call.name in function_calls_counter and function_calls_counter[function_call.name] > 1:
                function_calls_counter.pop(function_call.name)

        # Returns number of events found: int, important events: dict and the events:list
        return (event_counter, function_calls_counter, function_calls)

    def find_event_before_id(self, node_name, event_id):
        """Returns the most recent event on node_name whose id is strictly less than event_id."""
        for event in reversed(self.events_by_node[node_name]):
            if event.id < event_id:
                return event

    def check_order(self, fault_injected_event, window, origin_order):
        """Checks whether the function call sequence preceding a fault matches origin_order;
        returns False if any position differs or the fault was never injected (id == 0)."""
        if fault_injected_event.id == 0:
            print("Fault not injected")
            return False
        functions_before = self.get_functions_before(fault_injected_event.node, fault_injected_event.id, window)
        new_order = functions_before[2]
        for i in range(0, len(new_order) - 1):
            print("Comparing {} with {}".format(new_order[i].name, origin_order[i].name))
            if new_order[i].name != origin_order[i].name:
                return False
        return True

    def check_syscall_support(self, syscall_name):
        """Returns True if syscall_name is in the set of supported/injectable syscalls."""
        return check_if_syscall_supported(syscall_name) != "TEMP_EMPTY"

    def find_event_by_id_by_time(self, time, node):
        """Returns the id of the last event on node whose timestamp is <= time;
        returns 0 if the node has no recorded events."""
        event_id = 0
        # Sometimes there are no events in a node which suffered a fault
        if node in self.events_by_node:
            for event in self.events_by_node[node]:
                if event.time <= time:
                    event_id = event.id
                else:
                    break
            return event_id
        else:
            return event_id

    def write_to_file(self, filename):
        """Writes all events to filename, one per line, using their __repr__."""
        with open(filename, "w") as file:
            for event in self.events:
                file.write(str(event))


def get_fault_by_name(faults, fault_name):
    """Searches faults for the first entry whose name matches fault_name; prints a warning if not found."""
    for fault in faults:
        if fault.name == fault_name:
            return fault
    print("Failed to find previous fault ", fault_name, "faults is ", faults)


def compare_faults(buggy_run, normal_run):
    """Returns faults present in buggy_run whose group key is absent from normal_run;
    these are the faults unique to the buggy execution."""
    faults_buggy = group_faults(buggy_run)
    faults_normal = group_faults(normal_run)
    unique_faults = set(faults_buggy.keys()) - set(faults_normal.keys())
    faults = []
    for name in unique_faults:
        for fault in faults_buggy[name]:
            faults.append(fault)
    return faults


def calculate_faults_removed(buggy_run, normal_run):
    """Computes the percentage of buggy fault group keys that are absent from normal_run;
    a higher value means more of the buggy faults "disappeared" in the normal execution."""
    faults_buggy = group_faults(buggy_run)
    faults_normal = group_faults(normal_run)

    buggy_keys = set(faults_buggy.keys())
    normal_keys = set(faults_normal.keys())
    # print("Normal:", normal_keys)
    # print("Buggy:", buggy_keys)

    removed_keys = buggy_keys - normal_keys

    if not buggy_keys:
        return 0.0

    removed_pct = (abs(len(buggy_keys) - len(removed_keys)) / len(buggy_keys)) * 100.0

    # print("Removed PCT is", removed_pct)
    return removed_pct


def group_faults(fault_list):
    """Buckets faults into a dict keyed by type/syscall/target/timing; used to compare
    fault sets across runs without being sensitive to exact fault names."""
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
                faults[fault.type + str(fault.target) + str(fault.duration) + str(fault.start_time)].append(fault)
            else:
                faults[fault.type + str(fault.target) + str(fault.duration) + str(fault.start_time)] = [fault]
    return faults


def get_name_from_path(path):
    """Extracts the filename component from a full filesystem path."""
    return Path(path).name


def choose_faults(faults):
    """Deduplicates block_ips faults, removes network partitions caused by process pauses,
    ranks all remaining faults by state_score, and returns the top 10."""
    faults_choosen = []
    partitions = {}
    for fault in faults:
        # Group block_ips to reduce number of total faults
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
        if fault.type == "process_pause":
            faults_choosen.append(fault)

    for partition in partitions:
        faults_choosen.append(partitions[partition][0])

    benign_partitions_to_remove = []
    for fault in faults_choosen:
        if fault.type == "block_ips":
            for fault_ahead in faults_choosen:
                if fault_ahead.type == "process_pause":
                    start_pause = fault_ahead.start_time
                    end_pause = fault_ahead.start_time + fault_ahead.duration
                    partition_end = fault.start_time + fault.duration
                    target_match = fault.target == fault_ahead.target or fault_ahead.target in fault.fault_specifics.nodes_in
                    part_ends_in_pause = start_pause < partition_end < end_pause
                    if target_match and part_ends_in_pause:
                        benign_partitions_to_remove.append(fault.name)
                        continue

    for fault in faults_choosen:
        if fault.type == "block_ips":
            for fault_ahead in faults_choosen:
                if fault_ahead.type == "process_pause":
                    time_gap = abs(fault_ahead.start_time - (fault.start_time + fault.duration))
                    if time_gap <= 2000:
                        benign_partitions_to_remove.append(fault.name)
                        continue
    faults_selected = []
    for fault in faults_choosen:
        if fault.name not in benign_partitions_to_remove:
            faults_selected.append(fault)

    faults_selected.sort(key=lambda x: (x.state_score, -x.start_time), reverse=True)

    return faults_selected[:10]


def remove_numbers(input_string):
    """If input_string contains more than 10 digits, truncates everything from the
    first digit onward; otherwise returns it unchanged (normalizes path-based filenames)."""
    numbers = re.findall(r"\d", input_string)

    # Check if there are more than 10 numbers
    if len(numbers) > 10:
        # Find the index of the first number
        first_number_index = re.search(r"\d", input_string).start()
        # Remove everything from the first number onwards
        return input_string[:first_number_index]
    else:
        # Return the original string if there are 10 or fewer numbers
        return input_string


def build_fault_conditions(fault, functions_before, history_buggy):
    """Converts the unique function calls preceding a fault into user_function_condition
    objects that can trigger fault injection at the right program point."""
    begin_conditions = []
    for function_call, counter in functions_before[1].items():
        cond = user_function_condition()
        cond.binary_location = history_buggy.nodes[fault.target].binary
        cond.symbol = function_call
        cond.call_count = counter
        begin_conditions.append(cond)
    return begin_conditions


def get_time_for_fault(fault, faults_detected_time_sorted, fault_before, history):
    """Computes the trigger time for a fault, using the actual injection time of the
    preceding fault when available, or falling back to the original detected time."""
    time_fault_current = fault.start_time
    time_rounded_current = math.floor(time_fault_current / 10) * 10
    time_fault_before = get_fault_by_name(faults_detected_time_sorted, fault_before.name).start_time
    time_rounded_before = math.floor(time_fault_before / 10) * 10

    # If the previous fault did not occur in the last attempt we leverage the time before in the original
    # as we did for the previous fault
    fault_before_testing = next((x for x in history.faults_injected if fault_before.name in x.name), None)
    if fault_before_testing is None:
        time_rounded = time_rounded_before
    else:
        # Relax time
        ts = fault_before_testing.relative_time - 1000
        time_rounded = math.floor((ts / 1000000) / 10) * 10

    if time_rounded <= 0:
        print("Time in testing is sub 0, leverage a default 100 milli value")
        time_rounded = 100
    return time_rounded


def check_fault_order(faults_detected, faults_injected):
    """Verifies that every detected fault was actually injected, then checks that their
    relative ordering and timing (within a 2 s gap tolerance) match the detected sequence."""
    count_faults = 0
    for fault_detected in faults_detected:
        for fault_injected in faults_injected:
            if fault_detected.name in fault_injected.name:
                count_faults += 1
                break

    all_faults_were_injected = count_faults == len(faults_detected)
    if not all_faults_were_injected:
        print("Not all faults were injected")
        return all_faults_were_injected

    fault_names_detected = [f.name for f in faults_detected if "syscall" not in f.name and "extra" not in f.name]
    fault_names_injected = [f.name for f in faults_injected if "syscall" not in f.name and "extra" not in f.name]

    for i, fault_detected in enumerate(fault_names_detected):
        fault_detected_prod_time = next((x.start_time for x in faults_detected if x.name == fault_detected), None)
        fault_injected_prod_time = next(
            (x.start_time for x in faults_detected if x.name == fault_names_injected[i]),
            None,
        )
        gap = abs(fault_detected_prod_time - fault_injected_prod_time)
        if fault_names_injected[i] == fault_detected:
            continue
        elif gap > 2000:
            return False

    return True


def create_new_faults_for_state(history, fault):
    """Clones fault for every other node that runs the same binary, appending
    the node name and "extra" to distinguish the copies."""
    new_faults = []
    for node_name, node in history.nodes.items():
        if history.nodes[fault.target].binary == node.binary and fault.target != node_name:
            new_fault = deepcopy(fault)
            new_fault.name = new_fault.name + node_name + "extra"
            new_fault.target = node_name
            new_fault.traced = node_name
            new_faults.append(new_fault)
    return new_faults


def reset_offset_for_fault(faults_detected, fault, cond):
    """Finds all variants of fault in faults_detected and resets the offset of the
    user_function_condition matching cond.symbol back to 0."""
    for fault_extra in faults_detected:
        if fault.name in fault_extra.name:
            for i in range(0, len(fault_extra.begin_conditions)):
                if isinstance(fault_extra.begin_conditions[i], user_function_condition) and fault_extra.begin_conditions[i].symbol == cond.symbol:
                    fault_extra.begin_conditions[i].offset = 0
