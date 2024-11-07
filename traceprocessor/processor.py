import struct
import sys
import ipaddress

class Event:
    """
    A class representing a single event with attributes: Node, Pid, Tid, event_name, and time.
    """
    def __init__(self, node, pid, tid, event_name, time,ret,arg1,arg2,arg3,arg4):
        self.id = 0
        self.node = node
        self.pid = pid
        self.tid = tid
        self.event_name = event_name
        self.time = time
        self.relative_time = 0
        self.ret = ret

        if event_name == "connect":
            big_endian_bytes = struct.pack('<I', int(arg1))  # Pack as little-endian
            big_endian_int = struct.unpack('>I', big_endian_bytes)[0]  # Unpack as big-endian
            self.arg1 = ipaddress.IPv4Address(big_endian_int)
            self.arg2 = arg2
            
        elif event_name == "network_delay":
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
        


    def __repr__(self):
        return (f"Event(Node={self.node},Pid={self.pid},Tid={self.tid},"
                f"event_name={self.event_name}),Id={self.id},Relative_Time={self.format_time_ns()},Ret={self.ret},Arg1={self.arg1},Arg2={self.arg2},Arg3={self.arg3},Arg4={self.arg4}\n")
    
    def format_time_ns(self):
        seconds = self.relative_time // 1_000_000_000
        milliseconds = (self.relative_time % 1_000_000_000) // 1_000_000
        remaining_nanoseconds = self.relative_time % 1_000_000
        
        return f"{seconds} seconds, {milliseconds} milliseconds, {remaining_nanoseconds} nanoseconds"
    
    def check_if_fault(self):
        if "Fault" in self.event_name:
            return True
        if self.event_name == "network_delay":
            return True
        if self.event_name == "process_change":
            return True
        if self.event_name == "Start":
            return True
        if self.event_name == "End":
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
        self.end_time = 0
        
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

        if event_data['event_name'] == "Start":
            self.start_time = int(event_data['time'])
        if event_data['event_name'] == "End":
            self.end_time = int(event_data['time'])

        return Event(
            node=event_data['Node'],
            pid=event_data['Pid'],
            tid=event_data['Tid'],
            event_name=event_data['event_name'],
            time= int(event_data['time']),
            ret=event_data['ret'],
            arg1=event_data['arg1'],
            arg2=event_data['arg2'],
            arg3=event_data['arg3'],
            arg4=event_data['arg4'],
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
                
                # Append the event to the list for the corresponding node
                self.events.append(event)


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

            if event.pid not in self.pids[node_id]:
                self.pids[node_id].append(event.pid)
                self.new_pid_events[node_id].append(event)
        return self.events_by_node
    
    def print_events_after(self,node_name,event,window):
        events = self.events_by_node[node_name]
        for event_pos in range(0,len(events)-1):
            if events[event_pos].id == event.id:
                for i in range(0,window):
                    if(event_pos + i < len(events)):
                        print(events[event_pos+i])
                
    def count_events(self):
        self.event_counter = {}  
        for event in self.events:
            if event.event_name not in self.event_counter:
                self.event_counter[event.event_name] = 1
            else:
                self.event_counter[event.event_name] += 1

    def remove_events_with_name(self, event_name):
        self.events = [event for event in self.events if event.event_name != event_name]

    def order_events(self):
        for node_id in self.events_by_node:
            self.events_by_node[node_id].sort(key=lambda x: x.time)

        self.events.sort(key=lambda x: x.time)

        for event in self.events:
            event.relative_time = event.time - self.start_time

    def remove_outside_window_workload_events(self):
        self.events = [event for event in self.events if (event.time >= self.start_time and event.time <= self.end_time)]

    def process_history(self,history_file,time):
        self.read_and_parse_events(history_file)
        self.count_events() 
        self.remove_outside_window_workload_events()
        self.get_events_by_node()
        self.order_events()

def history_compare(normal_run,bug_run,node_name,window):
    last_window_events = bug_run[node_name][-window:]

    count_matching = 0

    normal_run_events = []

    for event in normal_run[node_name]:
        if event.event_name == last_window_events[count_matching].event_name:
            count_matching+=1
            normal_run_events.append(event)
        if count_matching == window:
            break
        else:
            count_matching = 0
            normal_run_events = []
    
    print(normal_run_events)


# Example usage
if __name__ == "__main__":

    mode = sys.argv[1]

    history_file = sys.argv[2]

    time = int(sys.argv[3])

    history = History()
    history.process_history(history_file,time)

    #Default window size
    window = 50

    if mode == "count":
        for event,count in history.event_counter.items():
            print(f"{event}: {count}")
    
    if mode == "node":
        node_name = sys.argv[4]

        if len(sys.argv) > 5:
            window = int(sys.argv[5])

        events = history.get_events_by_node()

        for event in history.events:
            if event.node == node_name:
                print(event)
            if event.check_if_fault():
                print(event)


    if mode == "process":
        for event in history.events:
                print(event)

    if mode == "search":

        if len(sys.argv) > 5:
            window = int(sys.argv[5])
        for event in history.events:
            if event.event_name == sys.argv[4]:
                print(event)

    if mode == "print_faults":
        for event in history.events:
            if "Fault" in event.event_name:
                print(event)
            if event.event_name == "network_delay":
                print(event)
            if event.event_name == "process_change":
                print(event)
            if event.event_name == "Start":
                print(event)
            if event.event_name == "End":
                print(event)

    #normal_run = sys.argv[1]  # Replace with the actual path to your event log file

    #bug_run = sys.argv[2]

    #node_name = sys.argv[3]

    #window = int(sys.argv[4])
    
    # Create an EventParser instance and read the events
    #history_normal = History()
    #history_normal.read_and_parse_events(normal_run)
    
    # Get and print the parsed events by node
    #events_by_node = history_normal.get_events_by_node()

    #history_bug = History()
    #history_bug.read_and_parse_events(bug_run)

    #events_by_node_bug_run = history_bug.get_events_by_node()

    #history_compare(events_by_node,events_by_node_bug_run,node_name,window)

    #print(events_by_node[node_name][-window:])
    #print(history_normal.new_pid_events[node_name])
    #print(events_by_node_bug_run[node_name][-window:])
    #print(history_bug.new_pid_events[node_name])

    #history_normal.print_events_after(node_name,history_normal.new_pid_events[node_name][2],15)
    
    #history_bug.print_events_after(node_name,history_bug.new_pid_events[node_name][2],15)