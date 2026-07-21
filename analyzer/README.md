# analyzer

Two modules that together turn raw execution traces and binaries into structured fault candidates.

---

## `trace_analysis.py`

Parses execution traces produced by the tracer and extracts fault candidates from them.

### Key classes

**`Event`**  
Represents a single traced event (syscall, process state change, network packet, function call). IP address arguments are decoded automatically for connect/network event types.

**`History`**  
The main analysis object. Typical usage:

```python
history = History()
history.parse_schedule("schedule.yaml")   # load node topology
history.process_history("trace.txt")      # read and order all events
faults = history.discover_faults(normal_history)  # extract fault candidates
```

`process_history` chains four steps: parse lines → sort by timestamp → group by node → compute per-node event IDs.

`discover_faults` walks all events and emits a `Fault` object for each:
- `sys_exit` with a supported syscall → **syscall error** fault
- `process_state_change` arg1=1 → **process kill** fault
- `process_state_change` arg1=4 → **process pause** fault
- `network_event` / `network_information` above a frequency threshold → **block_ips** fault

## `binary_parser.py`

Extracts instruction offsets from a compiled binary using `objdump`. Used to locate the exact address inside a function where a fault should be injected.

### Functions

| Function | Purpose |
|---|---|
| `calculate_offsets(binary, function)` | Offsets of all instructions in a function from its base address |
| `calculate_call_offsets(binary, function)` | Offsets of `call` instructions only |
| `calculate_plt_offsets(binary, function)` | Offsets of `@plt` call sites only |

Internally: `run_objdump` disassembles the binary, `extract_instructions` isolates the target function's lines, and the `extract_address` / `check_*_address` helpers filter and parse hex addresses from each line.
