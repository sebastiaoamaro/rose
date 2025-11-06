## Executor

### C
Contains the executor main code.

| File| Utility |
|----------|----------|
| main.c   | Boots up experiment, creates faults, runs experiments and cleanups the experiment.  |
| aux.c    | Auxiliary functions.  |
| fault_schedule.h    | Contains the structures which are created from the schedule.   |


| eBPF Map| Utility |
|----------|----------|
| faults   | [fault_nr] -> [fault] contains information related to the faults.  |
| relevant_state_info    | [pid,info_type (e.g. write/read)]->[relevant_states (values which matter),current_value,repeat (if it is a condition for a fault which repeats.)]  |
| fault_specification    | [pid,fault_type]->[fault_description](information about the fault).   |
| files    | files which are used as context for faults.   |
| auxiliary_info    | indicates the node which is the leader.   |
| node_status    | indicates if faults are to be injected nodes,    |
| pids  | contains a tree of the pids and their childs.   |
| nodes_Pid_translator  | translates a pid to the original_pid used in the creation of the previous maps.   |

### Kernel Module
Contains a function with compares strings.
