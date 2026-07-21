# executor

Loads and runs a fault schedule: eBPF programs observe syscalls, process state and network traffic on the nodes under test, and inject faults (process kill/pause, syscall error injection, network partitions, LazyFS crash-consistency faults) once a fault's conditions are met. A small kernel module supplies one kfunc used by the eBPF side.

---

## `src/`

### Entry points

| File | Purpose |
|---|---|
| `executor/executor.c` | Boots the experiment: builds the schedule, loads/pins the eBPF maps and programs, runs the setup/pre-workload/workload/cleanup phases, and injects faults as their conditions trigger. |
| `network_manager/network_manager.c` | Standalone binary that loads and attaches `tc.bpf.c` to a node's veth for network faults; `executor` launches it inside a container's network namespace via `nsenter` when a network fault needs to run. |

### eBPF programs (`*.bpf.c`)

| File | Purpose |
|---|---|
| `aux.bpf.c` | Declares the shared, pinned eBPF maps (faults, state info, node status, pid translation, blocked IPs, etc). No hooks attached - just the map layer other programs and `executor.c` share. |
| `fault_inject.bpf.c` | Main workhorse. Kprobes/ksyscalls/tracepoints on the traced syscalls and process lifecycle events (`write`, `read`, `close`, `open(at)`, `mkdir`, `stat`, `lseek`, `unlink`, `newfstatat`, `clone(3)`, `fsync`, `fdatasync`, `accept`, `connect`, process exec/fork), driving state tracking and fault injection via `state_processor.bpf.h`. |
| `tc.bpf.c` | TC (traffic control) program that drops/isolates packets for network faults (`block_ips`, `drop_packets`, `network_isolation`). |
| `uprobes.bpf.c` | Holds the maps used by dynamically-attached uprobes; the actual attach points (binary, function, offset) come from the fault schedule and are resolved/attached at runtime by `uprobes.c`, not by static `SEC()` hooks. |

### Shared headers

| File | Purpose |
|---|---|
| `bpf_shared.h` | Single source of truth for everything that must stay byte-identical between the eBPF programs and userspace: fault/state structs, map key/value and ring-buffer event types, and the `fault_type`/`stateinfo` enums. |
| `state_processor.bpf.h` | Core condition-matching/injection logic shared by every eBPF program: tracks per-node, per-fault condition state and calls `inject_fault` once a fault's conditions are satisfied. |
| `aux.h` | Userspace-only declarations built on top of `bpf_shared.h`: container (docker/lxc) lookup, process signal/kill/pause, `nsenter` argument building, process spawning (`custom_popen`). |
| `fault_schedule.h` | The rich, userspace-only domain model (`fault`, `node`, `tracer`, `execution_plan`, ...) parsed from the YAML schedule. Also includes `bpf_shared.h` for the sizes it shares with the eBPF side (e.g. `MAX_IPS_BLOCKED`). Its `.c` counterpart is generated - see below. |

### Userspace loaders

| File | Purpose |
|---|---|
| `aux.c` | Auxiliary functions: eBPF map setup, container pid/location lookup, process signal/kill/pause, `nsenter` argument building, and process spawning. |
| `fault_inject.c`, `uprobes.c` | Open, load and attach their respective eBPF skeleton (`uprobes.c` also resolves and attaches the schedule-driven uprobes). |
| `fault_schedule.c` | Checked-in placeholder (stub `get_node_count`/`get_fault_count`/`build_*` functions returning empty data). At build time, `schedule_parser/parser.py` regenerates this file from `schedule_parser/fault_schedule_template.c` plus the parsed YAML schedule, filling in the real nodes/faults/execution plan. |

### Vendored helpers (from bcc/libbpf-tools)

| File | Purpose |
|---|---|
| `btf_helpers.c/.h` | Supplies an embedded core BTF file (`ensure_core_btf`) when the running kernel doesn't expose its own BTF, needed for CO-RE relocations in `uprobes.c`. |
| `trace_helpers.c/.h` | Only `vmlinux_btf_exists()` is used (by `btf_helpers.c`); the rest (kallsyms/DSO symbol resolution, histogram printers, probe-existence checks) is unused here but kept for parity with upstream. |
| `uprobe_helpers.c/.h` | Resolves user-space binary/function symbol offsets for uprobe attachment. |

### eBPF maps

| Map | Utility |
|---|---|
| `faults` | `[fault_nr] -> [fault]` - information about each fault (conditions, occurrences, target, ...). |
| `relevant_state_info` | `[pid, info_type (e.g. write/read)] -> [relevant_states (values that matter), current_value, repeat]` (repeat: whether this is a condition for a repeating fault). |
| `faults_specification` | `[pid, fault_type] -> [fault_description]` - the actual error/return value to inject for syscall/network faults. |
| `files` | Files used as context for file-scoped faults. |
| `relevant_fd` | Per-pid set of file descriptors relevant to file-scoped faults. |
| `percpu_fileinfo` | Per-CPU scratch buffer used while resolving a traced fd's path. |
| `blocked_ips` | `[tc_key] -> [blocked IPs]` consumed by `tc.bpf.c` to drop/isolate network traffic. |
| `auxiliary_info` | Position `[0]` is the leader node; positions from `[1]` on are node current pids. |
| `nodes_status` | Whether a node is the leader, running normally, or has a fault pending injection. |
| `pids` | Tree of pids and their children (for killing a whole process tree). |
| `nodes_pid_translator` | Translates a node's current pid back to the original pid it was created with (all other maps are indexed by that original pid). |

---

## `kernel_module/`

Loadable kernel module (`rose.c`) exposing a single BPF kfunc, `bpf_strstr` - a bounded string-contains check used by `fault_inject.bpf.c` to match traced file paths against schedule conditions, with loop bounds small enough to satisfy the eBPF verifier.
