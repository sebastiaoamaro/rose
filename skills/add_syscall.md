# Add support for a new syscall fault

Adding a syscall (e.g. `lseek`, `unlink`, `sync_file_range`) as an injectable
fault touches the BPF injector, the Python schedule compiler, and a test
schedule. Follow the existing syscalls (`lseek`/`unlink`/`sync_file_range`
are the simplest recent examples; `newfstatat`/`fsync`/`fdatasync` show the
fd/file-specific variant) as templates.

## 1. `executor/src/bpf_shared.h`
- Add a `<NAME>_FAULT` entry to `enum fault_type` — pick an unused number.
- Add a `<NAME>_STATE` entry to `enum stateinfo` — pick an unused number.
- If the syscall also needs a *file-specific* fault variant (matching a
  particular filename/fd, like `newfstatat`/`fdatasync`/`openat`), add
  `<NAME>_FILE_FAULT` / `<NAME>_FILE_STATE` too.
- Bump `STATE_PROPERTIES_COUNT` (top of the file) by however many new
  `stateinfo` entries you added.

## 2. `executor/src/fault_inject.bpf.c`
- Add a `SEC("kprobe/__x64_sys_<name>")` (or `ksyscall/<name>` if you need
  typed args via `BPF_KPROBE`/`BPF_KSYSCALL`) handler.
- For a plain syscall with no fd/file matching, mirror `__x64_sys_lseek` /
  `__x64_sys_unlink`: get `pid`/`origin_pid`, call `process_current_state`
  once with `<NAME>_STATE, <NAME>_FAULT`.
- For a syscall that needs fd/filename matching, mirror `__x64_sys_fsync` /
  `newfstatat`: build a `struct sys_info`, and call `process_current_state`
  for the file-specific code first (if a match is found in the `files` map)
  and then the general code.
- No manual attach step is needed — kprobes declared with `SEC()` are
  auto-attached by the libbpf skeleton loader at startup.

## 3. `schedule_parser/faults.py`
- `get_fault_type_nr()`: add a `case "<name>":` under the `type == "syscall"`
  / `success == 0` branch returning `"<NAME>_FAULT"` (or the file variant
  under `success == 1` if applicable, following the `fdatasync` /
  `FDATASYNC_RET_FAULT` pattern).
- `check_if_syscall_supported()`: add a `case "<name>": return "<NAME>_FAULT"`
  so the schedule YAML parser accepts `details.name: <name>`.

## 4. `schedule_parser/conditions.py` — `get_cond_type_nr()`
**Easy to miss** — this is a separate mapping from `faults.py` and is used
for *end/begin conditions* that reference syscall counts (e.g.
`condition: {type: syscall, syscall_name: <name>}`), not for the fault
injection itself. Add a `case "<name>": return "<NAME>_STATE"` under the
`case 3:` (syscall-count condition) match — and under `case 2:` too if the
syscall has a file-specific state.

## 5. Write a test schedule in `rose/schedules/tests`
- Copy `sync_file_range_test.yaml` as a template: `faults.*.type: syscall`,
  `details.name: <name>`, a nonzero `return_value` (injected errno, e.g.
  `-5`), and a `time` begin_condition.
- If you added a condition-type-3 mapping in step 4, add a second fault or
  schedule that exercises a `begin_conditions`/`end_conditions` entry of
  `type: syscall, syscall_name: <name>` to verify the count-based condition
  resolves correctly, not just the fault injection itself.

## 6. Build and sanity-check
- Rebuild the BPF object: `make` in `executor/src` (or the project's usual
  build script) — a bad `STATE_PROPERTIES_COUNT`/enum mismatch between
  `bpf_shared.h` and the generated schedule C file fails at compile or,
  worse, silently corrupts unrelated fault state at runtime since it's a
  shared array size.
- Run the new test schedule via `run_schedule.sh` and confirm the fault
  actually fires (check tracer/BPF `bpf_printk` output or the run's fault
  log) and that the target syscall returns your injected `return_value`.
