import os
import shutil
import signal
import subprocess
import sys
import time
from copy import deepcopy

import yaml

from analyzer.binary_parser import (
    calculate_call_offsets,
    calculate_offsets,
    calculate_plt_offsets,
)
from analyzer.trace_analysis import (
    History,
    build_fault_conditions,
    calculate_faults_removed,
    check_fault_order,
    choose_faults,
    compare_faults,
    create_new_faults_for_state,
    get_time_for_fault,
    reset_offset_for_fault,
)
from schedule_parser.conditions import (
    time_cond,
    user_function_condition,
)


class BugReproduction:
    def __init__(self):
        self.schedule: str = ""
        self.oracle: str = ""
        self.result_folder: str = ""
        self.trace_location: str = ""
        self.buggy_trace: str = ""
        self.cleanup: str = ""
        self.binary: str = ""
        self.functions_file: str = ""
        self.profile: str = ""
        self.profile_functions: str = ""
        self.profile_files: str = ""


def parse_bug_reproduction(filename: str):
    file = open(filename, "r")

    bug_reproduction_text = yaml.safe_load(file)

    bug_reproduction_text = bug_reproduction_text["reproduction"]

    bug_reproduction = BugReproduction()

    if "schedule" in bug_reproduction_text:
        bug_reproduction.schedule = bug_reproduction_text["schedule"]
    else:
        print("  ✗ [config]  no 'schedule' parameter")

    if "oracle" in bug_reproduction_text:
        bug_reproduction.oracle = bug_reproduction_text["oracle"]
    else:
        print("  ✗ [config]  no 'oracle' parameter")

    if "result_folder" in bug_reproduction_text:
        bug_reproduction.result_folder = bug_reproduction_text["result_folder"]
    else:
        print("  ✗ [config]  no 'result_folder' parameter")

    if "trace_location" in bug_reproduction_text:
        bug_reproduction.trace_location = bug_reproduction_text["trace_location"]
    else:
        print("  ✗ [config]  no 'trace_location' parameter")

    if "buggy_trace" in bug_reproduction_text:
        bug_reproduction.buggy_trace = bug_reproduction_text["buggy_trace"]
    else:
        print("  ✗ [config]  no 'buggy_trace' parameter")

    if "cleanup" in bug_reproduction_text:
        bug_reproduction.cleanup = bug_reproduction_text["cleanup"]

    if "binary" in bug_reproduction_text:
        bug_reproduction.binary = bug_reproduction_text["binary"]

    if "functions_file" in bug_reproduction_text:
        bug_reproduction.functions_file = bug_reproduction_text["functions_file"]

    if "profile" in bug_reproduction_text:
        bug_reproduction.profile = bug_reproduction_text["profile"]
    if "profile_functions" in bug_reproduction_text:
        bug_reproduction.profile_functions = bug_reproduction_text["profile_functions"]
    if "profile_files" in bug_reproduction_text:
        bug_reproduction.profile_files = bug_reproduction_text["profile_files"]

    return bug_reproduction


RUN_SCHEDULE_LOG = "/tmp/run_schedule.log"

# Exit codes that mean the executor was killed by a fatal signal (128 + signo):
# SIGILL 4, SIGABRT 6, SIGBUS 7, SIGFPE 8, SIGSEGV 11 -> 132, 134, 135, 136, 139.
# 124 is our own sentinel for "run_schedule.sh timed out" (see _run_schedule_once).
_CRASH_EXIT_CODES = frozenset({124, 132, 134, 135, 136, 139})
_CRASH_LOG_MARKERS = ("Segmentation fault", "SIGSEGV", "core dumped", "Aborted (core")
CRASH_RETRY_LIMIT = 3  # -> up to CRASH_RETRY_LIMIT + 1 attempts total
CRASHED_SCHEDULES_LOG = "/tmp/crashed_schedules.txt"
# Cap on the post-crash cleanup script (docker compose down + log collection).
CLEANUP_TIMEOUT = 180
# Hard cap on a single run_schedule.sh invocation. The schedule itself is bounded
# by its maximum_time (~180s) plus build + server startup; this is a generous
# outer bound so a wedged run can't stall the whole sweep forever.
RUN_SCHEDULE_TIMEOUT = 1200


def _kill_process_group(process) -> None:
    """Best-effort SIGTERM-then-SIGKILL of the session started for run_schedule.sh.
    A segfaulted executor leaves orphans (etcd, containers) that inherit our fds
    and would otherwise wedge the next attempt / the output pipe.

    run_schedule.sh's run_main() launches the real work via `sudo -E .../executor`,
    so `executor` (and the `tracer` it spawns) run as root while staying in this
    same process group. A plain os.killpg() from this (unprivileged) process can
    only signal same-UID members - per POSIX semantics it still returns
    successfully (it reached run_schedule.sh itself) while *silently* failing to
    touch the root-owned executor/tracer, leaking them indefinitely. `sudo kill`
    on the group grants the privilege needed to actually reach those too."""
    try:
        pgid = os.getpgid(process.pid)
    except (ProcessLookupError, PermissionError):
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        subprocess.run(["sudo", "kill", f"-{int(sig)}", f"-{pgid}"], capture_output=True)
        try:
            process.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            continue


def _run_schedule_once(schedule: str, timeout: int = RUN_SCHEDULE_TIMEOUT) -> int:
    """Run /vagrant/run_schedule.sh once, redirecting merged stdout/stderr into
    RUN_SCHEDULE_LOG (truncated each call), and return the process exit code.

    stdout goes straight to the log file (not through a PIPE we drain by hand):
    the executor's grandchildren - the etcd server, the r/w containers - inherit
    the child's stdout, so on a segfault they keep a pipe write-end open and a
    readline() relay loop blocks on it forever (never EOF, never a new line),
    which is exactly the "got stuck, never retried" hang. With a real file there
    is no pipe to keep open, and wait() returns as soon as run_schedule.sh exits.

    The child runs in its own session so its orphans can be killed as a group on
    timeout or on the way out; a timeout returns 124 (treated as a crash upstream
    -> retried)."""
    command = ["/vagrant/run_schedule.sh", schedule]
    with open(RUN_SCHEDULE_LOG, "w") as file:
        with subprocess.Popen(
            command,
            stdout=file,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            text=True,
            errors="replace",
            start_new_session=True,
        ) as process:
            try:
                process.wait(timeout=timeout)
                return process.returncode
            except subprocess.TimeoutExpired:
                print(f"  ✗ [run]  run_schedule.sh exceeded {timeout}s; killing it")
                _kill_process_group(process)
                return 124
            finally:
                # Reap whatever the run left behind (a crashed executor's etcd /
                # containers) so the next attempt starts from a clean box.
                _kill_process_group(process)


def _run_schedule_crashed(returncode: int) -> bool:
    """True if the last run looks like the executor died on a fatal signal - by
    exit code, by the run_schedule.sh EXECUTOR_EXIT sentinel, or by a crash
    marker in RUN_SCHEDULE_LOG (fallback for when the shell exit code is masked)."""
    if returncode in _CRASH_EXIT_CODES:
        return True
    try:
        with open(RUN_SCHEDULE_LOG, "r", errors="replace") as f:
            log = f.read()
    except OSError:
        return False
    for line in log.splitlines():
        if line.startswith("EXECUTOR_EXIT="):
            try:
                if int(line.split("=", 1)[1].strip()) in _CRASH_EXIT_CODES:
                    return True
            except ValueError:
                pass
    return any(marker in log for marker in _CRASH_LOG_MARKERS)


def _run_schedule_cleanup(schedule: str) -> None:
    """Run the schedule's execution_plan.cleanup.script (normally a
    `docker compose down`). The executor runs this itself on a clean exit
    (executor.c cleanup: label), but a segfault - or the SIGKILL we send on a
    timeout - skips it, leaving the cluster containers and their servers running.
    Best effort: a missing/broken schedule must never block the retry loop."""
    try:
        with open(schedule, "r") as f:
            spec = yaml.safe_load(f) or {}
        script = (
            (spec.get("execution_plan") or {}).get("cleanup") or {}
        ).get("script", "")
    except (OSError, yaml.YAMLError) as e:
        print(f"  ✗ [cleanup]  could not read {schedule}: {e}")
        return
    if not script:
        return
    print(f"  ⟳ [cleanup]  post-crash teardown: {script}")
    run_cleanup(script, timeout=CLEANUP_TIMEOUT)


def run_reproduction(schedule: str, max_crash_retries: int = CRASH_RETRY_LIMIT):
    for attempt in range(max_crash_retries + 1):
        try:
            returncode = _run_schedule_once(schedule)
        except Exception as e:
            print(f"  ✗ [run]  unexpected error: {e}")
            return

        if not _run_schedule_crashed(returncode):
            if returncode != 0:
                print(f"  ✗ [run]  exit code {returncode}")
            return

        # The executor died before its own cleanup: label ran, so its
        # docker-compose teardown was skipped - do it now so orphaned containers
        # / servers don't wedge the next attempt (or linger after we give up).
        _run_schedule_cleanup(schedule)

        if attempt < max_crash_retries:
            print(
                f"  ⟳ [run]  executor crashed (exit {returncode}); "
                f"rerun {attempt + 1}/{max_crash_retries}"
            )
            continue

        print(
            f"  ✗ [run]  executor crashed on every attempt "
            f"({max_crash_retries + 1}×); giving up: {schedule}"
        )
        try:
            with open(CRASHED_SCHEDULES_LOG, "a") as f:
                f.write(
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{schedule}\trc={returncode}\n"
                )
        except OSError:
            pass


def check_oracle(oracle: str, run: str, result_folder: str, name_in_log: bool = True):
    """`name_in_log=False` leaves the run name out of the clean/failed lines, for
    callers that already announced the run (the bug banner always names it)."""
    command = ["sudo", oracle, run, result_folder]
    who = f"{run}: " if name_in_log else ""

    buggy_run = False
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,  # Capture stdout and stderr
            text=True,  # Decode output as text
            check=True,  # Raise exception on non-zero exit code
        )
        if result.stdout != "\n":
            buggy_run = True
            # Persist the oracle's own output (the evidence for the bug) next to the
            # schedule/log files for this run, so it survives after this process exits -
            # collect_history() already claims "<run>.txt" for the workload trace, so
            # this uses a distinct suffix to avoid colliding with it.
            bug_log_path = result_folder + run + ".oracle_log.txt"
            with open(bug_log_path, "w") as f:
                f.write(result.stdout)
            print(f"  [oracle]  BUG CONFIRMED  ->  {run}")
            print(f"  [oracle]  {result.stdout.strip()}")
            print(f"  [oracle]  log -> {bug_log_path}")
        else:
            print(f"  [oracle]  {who}clean")
    except subprocess.CalledProcessError as e:
        print(f"  ✗ [oracle]  {who}oracle failed -> {e.stderr.strip()}")

    return buggy_run


def collect_history(trace_location: str, result_folder: str, run: str, announce: bool = True):
    location = result_folder + run + ".txt"
    if announce:
        print(f"  [collect]  {trace_location}  ->  {location}")
    command = ["sudo", "mv", trace_location, location]
    try:
        # Start the process
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"  ✗ [collect]  {e.stderr.strip()}")
        exit()
    return location


def run_cleanup(cleanup: str, timeout=None):
    if len(cleanup) == 0:
        return

    command = ["sh", cleanup]
    try:
        # Start the process
        result = subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        print(f"  ✗ [cleanup]  timed out after {timeout}s: {cleanup}")
    except subprocess.CalledProcessError as e:
        print(f"  ✗ [cleanup]  {e.stderr.strip()}")


def move_file(source_path, destination_path):
    try:
        shutil.copy(source_path, destination_path)
        print(f"  ✓ moved  {source_path}  ->  {destination_path}")
    except FileNotFoundError:
        print(f"  ✗ [move]  file not found: {source_path}  ->  {destination_path}")
        exit()
    except PermissionError:
        print(f"  ✗ [move]  no permissions: {source_path}  ->  {destination_path}")
        exit()
    except Exception as e:
        print(f"  ✗ [move]  {e}: {source_path}  ->  {destination_path}")
        exit()


def reproduce_bug(bug_specification: str):
    start_time = time.time()
    bug_reproduction = parse_bug_reproduction(bug_specification)
    print("  [repro]  running faultless schedule")
    run_reproduction(bug_reproduction.schedule)
    trace_location = collect_history(bug_reproduction.trace_location, bug_reproduction.result_folder, "normal")
    run_cleanup(bug_reproduction.cleanup)

    # Parse faultless schedule
    print(f"  [repro]  parsing faultless schedule: {trace_location}")
    history = History()
    history.parse_schedule(bug_reproduction.schedule)
    history.process_history(trace_location)
    faults_normal = history.discover_faults(None)

    # Parse buggy trace
    print(f"  [repro]  parsing buggy trace: {bug_reproduction.buggy_trace}")
    history_buggy = History()
    history_buggy.parse_schedule(bug_reproduction.schedule)
    history_buggy.process_history(bug_reproduction.buggy_trace)
    faults_buggy = history_buggy.discover_faults(history)
    history_buggy.write_to_file("/tmp/parsed_buggy_history.txt")
    fault_removal_pct = calculate_faults_removed(faults_buggy, faults_normal)
    faults_detected = compare_faults(faults_buggy, faults_normal)

    runs_counter = 1
    # First attempt run a first schedule, based on first level context information
    faults_detected = choose_faults(faults_detected)
    print(f"  [repro]  faults to use: {faults_detected}")
    schedule_location = "/tmp/temp_sched.yaml"
    buggy_schedules = []

    print("  [repro]  level 1: first guess")
    buggy_run = run_test(bug_reproduction, faults_detected)
    schedules_generated = 1
    history = collect_and_parse(
        bug_reproduction.trace_location,
        bug_reproduction.result_folder,
        schedule_location,
        "first_guess",
    )
    if buggy_run:
        print("  !! [repro]  buggy run on first attempt, checking replay rate")
        (runs, replay_rate) = check_replay_rate(schedule_location, bug_reproduction)
        runs_counter += runs
        if replay_rate >= 75:
            return end_reproduction(
                replay_rate,
                runs_counter,
                schedules_generated,
                start_time,
                schedule_location,
                fault_removal_pct,
            )

        schedule = save_schedule(schedule_location, bug_reproduction.result_folder, "first_guess")
        buggy_schedules.append(schedule)

    print("  [repro]  level 2: what happened before?")

    # Fault we are contextualizing
    fault_counter = 0
    # Faults in production ordered by time
    faults_detected_time_sorted = sorted(faults_detected, key=lambda x: x.start_time)
    # Best replay rate found
    replay_rate = 0
    # Number of faults depending on a function
    functions_to_analyze = 0
    # Holds the last correct history (preserves fault order and condition order)
    last_history = history

    for fault in faults_detected:
        # Ignore faults created by us, temporary remove after refactor
        if "extra" in fault.name:
            continue

        print(f"  [repro]  contextualizing fault: {fault}")
        fault_occuring = True
        condition_order = True
        fault_order = True
        first_buggy_schedule_for_fault = True

        if fault.type == "syscall" and functions_to_analyze == 0:
            call_count = 1

            while replay_rate < 75 and fault_occuring and call_count < 100:
                fault.begin_conditions[0].call_count = call_count
                print(f"  [repro]  testing fault: {faults_detected[fault_counter]}")

                # If we have a lot of system calls faults they break workloads
                buggy_run = run_test(bug_reproduction, faults_detected[fault_counter : fault_counter + 1])
                schedules_generated += 1

                # Normal Rose behavior
                # buggy_run = run_test(bug_reproduction,faults_detected)

                runs_counter += 1
                total_faults = 0
                if buggy_run:
                    (runs, replay_rate) = check_replay_rate(schedule_location, bug_reproduction)
                    runs_counter += runs
                    if replay_rate >= 75:
                        break
                    run_name = str(fault_counter) + ":" + str(call_count)
                    schedule = save_schedule(schedule_location, bug_reproduction.result_folder, run_name)
                    buggy_schedules.append(schedule)
                else:
                    history = collect_and_parse(
                        bug_reproduction.trace_location,
                        bug_reproduction.result_folder,
                        schedule_location,
                        str(call_count),
                    )
                    if len(history.faults_injected) == 0:
                        fault_occuring = False
                    for fault_injected_event in history.faults_injected:
                        if fault.name in fault_injected_event.name:
                            fault_occuring = True
                        else:
                            fault_occuring = False
                    if not fault_occuring:
                        fault_counter += 1

                call_count += 1

            if replay_rate > 75:
                return end_reproduction(
                    replay_rate,
                    runs_counter,
                    schedules_generated,
                    start_time,
                    schedule_location,
                    fault_removal_pct,
                )

        if fault.type in ("process_kill", "process_pause", "block_ips"):
            # Holds if we are amplifying the fault
            amplification = False
            # Chain construction iterations
            count = 1
            # Last size of chain
            last_event_counter_value = 0
            # Number of unique events in previous window
            previous_number_unique_events = -1
            # Last used conditions for fault
            last_used_conditions = deepcopy(fault.begin_conditions)
            # Faults from amplification
            last_created_aux_faults = []

            # Loop while we do not find a schedule, the fault is occuring, the conditions and faults are in correct order, or we achieve 7 conditions
            while replay_rate < 75 and fault_occuring and condition_order and fault_order and len(last_used_conditions) < 7:
                # Unique functions which precede the fault
                functions_before = []
                window = count
                if not amplification:
                    functions_before = history_buggy.get_functions_before(fault.target, fault.event_id, window)
                    # If we saw all functions before the fault
                    if last_event_counter_value == functions_before[0]:
                        print(f"  [repro]  all functions seen  LECV={last_event_counter_value}  FUNC_BEFORE={functions_before[0]}")
                        fault_counter += 1
                        break
                    # If incrementing the window did not increase the number of unique functions
                    elif len(functions_before[1]) <= previous_number_unique_events:
                        print("  [repro]  unique events did not change, breaking")
                        # BREAK SKIPS DUPLICATES
                        fault_counter += 1
                        break

                        # KEEP GOING
                        # count += 1
                        # continue
                    # If there are no unique functions
                    elif len(functions_before[1]) == 0:
                        print("  [repro]  no unique functions")
                        last_event_counter_value = functions_before[0]
                        previous_number_unique_events = len(functions_before[1])
                        # New but makes sense
                        count += 1
                        continue
                    # Update values
                    else:
                        last_event_counter_value = functions_before[0]
                        previous_number_unique_events = len(functions_before[1])
                # If we are amplyfing just recalculate functions_before
                else:
                    functions_before = history_buggy.get_functions_before(fault.target, fault.event_id, window)

                print(f"  [repro]  using chain: {functions_before}")
                # Add functions to Fault conditions
                fault.begin_conditions = build_fault_conditions(fault, functions_before, history_buggy)

                # Add time condition to Fault
                cond = time_cond()
                time_rounded = 0
                current_index = faults_detected_time_sorted.index(fault)
                fault_before = None
                # Find fault which occured before
                for prev_index in range(current_index - 1, -1, -1):
                    prev_fault = faults_detected_time_sorted[prev_index]
                    if "syscall" not in prev_fault.name:
                        fault_before = prev_fault
                        break
                # If there is no fault (first_one) we leverage symbols
                if fault_before is None:
                    print("  [repro]  no previous fault")
                    time_rounded = 0
                else:
                    time_rounded = get_time_for_fault(fault, faults_detected_time_sorted, fault_before, last_history)
                if time_rounded != 0:
                    cond.time = time_rounded
                    fault.begin_conditions.append(cond)
                    fault.start_time = time_rounded

                faults_created = 1
                faults_to_inject = []
                new_faults = []
                # Replicates a state for all faults that share the binary to account for randomness
                if amplification:
                    new_faults = create_new_faults_for_state(history, fault)
                    faults_created = faults_created + len(new_faults)
                    faults_to_inject = new_faults + faults_detected
                    print("  [repro]  amplified")
                else:
                    faults_to_inject = faults_detected

                # Test schedule with new conditions
                run_name = str(fault_counter) + ":" + str(count)
                buggy_run = run_test(bug_reproduction, faults_to_inject)
                schedules_generated += 1
                runs_counter += 1
                if buggy_run and first_buggy_schedule_for_fault:
                    (runs, replay_rate) = check_replay_rate(schedule_location, bug_reproduction)
                    runs_counter += runs
                    if replay_rate >= 75:
                        break
                    first_buggy_schedule_for_fault = False
                    schedule = save_schedule(schedule_location, bug_reproduction.result_folder, run_name)
                    buggy_schedules.append(schedule)
                elif buggy_run:
                    schedule = save_schedule(schedule_location, bug_reproduction.result_folder, run_name)
                    buggy_schedules.append(schedule)

                # If it is not a buggy_run we need to check if the fault we are changing occurred
                history = collect_and_parse(
                    bug_reproduction.trace_location,
                    bug_reproduction.result_folder,
                    schedule_location,
                    run_name,
                )
                total_faults = 0
                fault_occuring = next(
                    (True for x in history.faults_injected if fault.name in x.name),
                    False,
                )

                fault_order = True

                if not fault_occuring:
                    print("  [repro]  fault did not occur")
                    if amplification:
                        fault.begin_conditions = deepcopy(last_used_conditions)
                        continue
                    # We do not amplify network delays
                    elif fault.type != "block_ips":
                        print(f"  [repro]  fault_occuring={fault_occuring}  cond_order={condition_order}  fault_order={fault_order}  len_luc={len(last_used_conditions)}")
                        fault_occuring = True
                        amplification = True
                        continue

                elif not amplification:
                    fault_order = check_fault_order(faults_detected_time_sorted, history.faults_injected)

                    print(f"  [repro]  time_sorted: {faults_detected_time_sorted}")
                    print(f"  [repro]  injected:    {history.faults_injected}")

                if not fault_order and not amplification:
                    print("  [repro]  skipped: faults out of order")
                    fault_counter += 1
                    fault.begin_conditions = deepcopy(last_used_conditions)
                    continue

                # increment window multiplier
                count += 1
                for fault_injected_event in history.faults_injected:
                    if fault.name in fault_injected_event.name:
                        print("  [repro]  checking order")
                        condition_order = history.check_order(
                            fault_injected_event,
                            window,
                            functions_before[2],
                        )
                        print(f"  [repro]  condition_order={condition_order}  window={functions_before[2]}")
                        if not condition_order:
                            fault.begin_conditions = deepcopy(last_used_conditions)
                        else:
                            last_used_conditions = deepcopy(fault.begin_conditions)
                            last_history = history
                            functions_to_analyze += 1
                        total_faults += 1
                        last_created_aux_faults = new_faults
                # If the faults we created were all called then it is not a random sequence
                print(f"  [repro]  total_faults={total_faults}  faults_created={faults_created}")
                if amplification:
                    # If we amplified and not all faults occurred we keep amplification
                    amplification = total_faults != faults_created
                if not condition_order:
                    fault_counter += 1
                    fault.begin_conditions = deepcopy(last_used_conditions)
                    for fault in last_created_aux_faults:
                        fault.begin_conditions = deepcopy(last_used_conditions)
                        faults_detected.append(fault)

        if replay_rate > 75:
            return end_reproduction(
                replay_rate,
                runs_counter,
                schedules_generated,
                start_time,
                schedule_location,
                fault_removal_pct,
            )

    schedule_location = write_new_schedule(bug_reproduction.schedule, faults_detected, "/tmp/temp_sched.yaml")

    # Third attempts run schedules based on third level context information
    fault_to_condition_map_plt = {}
    fault_to_offsets_plt = []

    fault_to_condition_map_call = {}
    fault_to_offsets_call = []

    if not bug_reproduction.binary == "":
        print("  [repro]  level 3.1: plt offsets")
        faults_with_function_counter = 0
        for fault in reversed(faults_detected):
            if "extra" in fault.name:
                continue
            # No bugs we reproduce need this
            if fault.type == "syscall":
                continue
            if fault.type in ("process_kill", "process_pause", "block_ips"):
                for cond in fault.begin_conditions:
                    if isinstance(cond, user_function_condition):
                        offsets = calculate_plt_offsets(bug_reproduction.binary, cond.symbol)
                        # No plt calls found
                        if len(offsets) == 0:
                            break
                        fault_to_condition_map_plt[fault.name] = (
                            faults_with_function_counter,
                            cond.symbol,
                        )
                        fault_to_offsets_plt.append(offsets)
                        faults_with_function_counter += 1
                        (runs, replay_rate, buggy_schedules_3_1) = test_offsets_for_fault(
                            offsets,
                            faults_detected,
                            fault,
                            bug_reproduction,
                            runs_counter,
                            schedule_location,
                            cond,
                        )
                        if replay_rate > 75:
                            runs_counter += runs
                            return end_reproduction(
                                replay_rate,
                                runs_counter,
                                schedules_generated,
                                start_time,
                                schedule_location,
                                fault_removal_pct,
                            )
                            return
                        for buggy_schedule in buggy_schedules_3_1:
                            buggy_schedules.append(buggy_schedule)
                        # Reset offsets back to 0
                        reset_offset_for_fault(faults_detected, fault, cond)
                        break

        print("  [repro]  level 3.2: call offsets")
        faults_with_function_counter = 0
        for fault in reversed(faults_detected):
            if "extra" in fault.name:
                continue
            # No bugs we reproduce need this
            if fault.type == "syscall":
                continue
            if fault.type in ("process_kill", "process_pause", "block_ips"):
                for cond in fault.begin_conditions:
                    if isinstance(cond, user_function_condition):
                        offsets = calculate_call_offsets(bug_reproduction.binary, cond.symbol)
                        # No plt calls found
                        if len(offsets) == 0:
                            break
                        fault_to_condition_map_call[fault.name] = (
                            faults_with_function_counter,
                            cond.symbol,
                        )
                        fault_to_offsets_call.append(offsets)
                        faults_with_function_counter += 1
                        (runs, replay_rate, buggy_schedules_3_2) = test_offsets_for_fault(
                            offsets,
                            faults_detected,
                            fault,
                            bug_reproduction,
                            runs_counter,
                            schedule_location,
                            cond,
                        )
                        if replay_rate > 75:
                            runs_counter += runs
                            return end_reproduction(
                                replay_rate,
                                runs_counter,
                                schedules_generated,
                                start_time,
                                schedule_location,
                                fault_removal_pct,
                            )
                        for buggy_schedule in buggy_schedules_3_2:
                            buggy_schedules.append(buggy_schedule)
                        # Reset offsets back to 0
                        reset_offset_for_fault(faults_detected, fault, cond)
                        break

    print("  [repro]  all levels done, testing buggy schedules")
    # Final test of all schedules which showed the bug
    best_rr_rate = 0
    best_schedule = ""
    for buggy_schedule in reversed(buggy_schedules):
        runs_counter += 10
        replay_rate = check_replay_rate_post_phase(buggy_schedule, bug_reproduction)
        if replay_rate >= 60:
            return end_reproduction(
                replay_rate,
                runs_counter,
                schedules_generated,
                start_time,
                buggy_schedule,
                fault_removal_pct,
            )
        if replay_rate > best_rr_rate:
            best_rr_rate = replay_rate
            best_schedule = buggy_schedule

    return end_reproduction(
        replay_rate,
        runs_counter,
        schedules_generated,
        start_time,
        best_schedule,
        fault_removal_pct,
    )


def run_test(bug_reproduction, faults_detected):
    schedule_location = write_new_schedule(bug_reproduction.schedule, faults_detected, "/tmp/temp_sched.yaml")
    run_reproduction(schedule_location)
    buggy_run = check_oracle(bug_reproduction.oracle, str(0), bug_reproduction.result_folder)
    run_cleanup(bug_reproduction.cleanup)
    return buggy_run


def run_schedule(schedule, faults):
    run_reproduction(schedule)
    return schedule


def collect_and_parse(trace_location, result_folder, schedule_location, name):
    history_location = collect_history(trace_location, result_folder, name)
    history = History()
    history.parse_schedule(schedule_location)
    history.process_history(history_location)
    return history


def check_replay_rate(schedule, bug_reproduction):
    print(f"  [rr]  testing replay rate: {schedule}")
    buggy_runs_counter = 0
    normal_runs_counter = 0
    for i in range(0, 10):
        run_reproduction(schedule)
        buggy_run = check_oracle(bug_reproduction.oracle, str(0), bug_reproduction.result_folder)
        run_cleanup(bug_reproduction.cleanup)
        if buggy_run:
            buggy_runs_counter += 1
        else:
            normal_runs_counter += 1
        if normal_runs_counter == 3:
            print("  [rr]  cannot exceed 70%, aborting")
            return (buggy_runs_counter + normal_runs_counter, 0)
    replay_rate = (buggy_runs_counter * 100) / 10
    print(f"  [rr]  replay_rate={replay_rate:.0f}%")
    return (buggy_runs_counter + normal_runs_counter, replay_rate)


def check_replay_rate_post_phase(schedule, bug_reproduction):
    print(f"  [rr]  testing replay rate: {schedule}")
    buggy_runs_counter = 0
    normal_runs_counter = 0
    for i in range(0, 10):
        run_reproduction(schedule)
        buggy_run = check_oracle(bug_reproduction.oracle, str(0), bug_reproduction.result_folder)
        run_cleanup(bug_reproduction.cleanup)
        if buggy_run:
            buggy_runs_counter += 1
    replay_rate = (buggy_runs_counter * 100) / 10
    print(f"  [rr]  replay_rate={replay_rate:.0f}%")
    return replay_rate


def write_new_schedule(base_schedule, faults, output_schedule, maximum_time=0):
    file = open(base_schedule, "r")
    base_schedule = yaml.safe_load(file)

    exe_plan = {"execution_plan": base_schedule["execution_plan"]}
    if maximum_time != 0:
        exe_plan["execution_plan"]["maximum_time"] = maximum_time
    nodes = {"nodes": base_schedule["nodes"]}

    schedule_location = output_schedule
    with open(schedule_location, "w") as file:
        yaml.dump(exe_plan, file, default_flow_style=False)
        yaml.dump(nodes, file, default_flow_style=False)

        faults_dict = {"faults": {}}

        for fault in faults:
            fault_dict = fault.to_yaml()
            faults_dict["faults"][fault.name] = fault_dict

        yaml.dump(faults_dict, file, default_flow_style=False, sort_keys=False)

    return schedule_location


def save_schedule(schedule_location, result_folder, run_name):
    location = result_folder + run_name + ".yaml"
    command = ["sudo", "cp", schedule_location, location]
    try:
        # Start the process
        result = subprocess.run(
            command,
            capture_output=True,  # Capture stdout and stderr
            text=True,  # Decode output as text
            check=True,  # Raise exception on non-zero exit code
        )
        # print("Output from collect_history:")
        # print(result.stdout)  # Standard output
    except subprocess.CalledProcessError as e:
        print(f"  ✗ [save]  {e.stderr.strip()}")
        exit()

    return location


def end_reproduction(replay_rate, runs, schedules_generated, start_time, schedule, fault_removal_pct):
    end_time = time.time()
    elapsed_time = end_time - start_time
    if replay_rate >= 60:
        print(f"  ✓ reproduction done  rr={replay_rate:.0f}%  runs={runs}  time={elapsed_time:.1f}s  schedule={schedule}")
    else:
        print(f"  ✗ reproduction failed  rr={replay_rate:.0f}%  runs={runs}  time={elapsed_time:.1f}s  schedule={schedule}")
    return (
        replay_rate,
        runs,
        schedules_generated,
        elapsed_time,
        schedule,
        fault_removal_pct,
    )


def test_offsets_for_fault(
    offsets,
    faults_detected,
    fault,
    bug_reproduction,
    runs_counter,
    schedule_location,
    cond,
):
    buggy_schedules = []
    for offset in offsets:
        # Change offsets of faults
        for fault_extra in faults_detected:
            if fault.name in fault_extra.name:
                for i in range(0, len(fault_extra.begin_conditions)):
                    if isinstance(fault_extra.begin_conditions[i], user_function_condition) and fault_extra.begin_conditions[i].symbol == cond.symbol:
                        fault_extra.begin_conditions[i].offset = offset
        buggy_run = run_test(bug_reproduction, faults_detected)
        runs_counter += 1
        if buggy_run:
            run_name = fault.name + str(offset)
            schedule = save_schedule(schedule_location, bug_reproduction.result_folder, run_name)
            buggy_schedules.append(schedule)
            (runs, replay_rate) = check_replay_rate(schedule_location, bug_reproduction)
            runs_counter += runs
            if replay_rate >= 75:
                return (runs_counter, replay_rate, buggy_schedules)
    return (runs_counter, 0, buggy_schedules)


if __name__ == "__main__":
    bug_specification = sys.argv[1]
    reproduce_bug(bug_specification)
