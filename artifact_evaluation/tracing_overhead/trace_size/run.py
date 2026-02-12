import os
import selectors
import subprocess
import time

from reproduction import (
    History,
    collect_history,
    parse_bug_reproduction,
    run_cleanup,
    run_reproduction,
)

_MIB = 1024 * 1024


def bytes_to_mib(num_bytes: int) -> float:
    return num_bytes / _MIB


def run_collect_bpf_logs_script(
    script_path="/vagrant/artifact_evaluation/tracing_overhead/trace_size/scripts/collect_bpf_logs.sh",
    output_path="/tmp/bpf_logs.txt",
    timeout=10,
):
    """Run `collect_bpf_logs.sh` and return the collected content from `/tmp/bpf_logs.txt`."""
    proc = subprocess.run(
        ["bash", script_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )

    try:
        with open(output_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        content = ""

    return {
        "script_returncode": proc.returncode,
        "script_output": proc.stdout,
        "output_path": output_path,
        "output_content": content,
    }


def count_reset_appears(path):
    """Count occurrences of the exact substring 'Reset' in a text file.

    - Reads the file line-by-line (streaming) to avoid loading large files into memory.
    - Uses 'utf-8' with errors='replace' to be resilient to unexpected bytes in the bpf log.
    - Matching is case-sensitive.
    """
    needle = "Reset"
    count = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            count += line.count(needle)
    return count


def get_file_stats(path):
    """Return (num_lines, size_bytes) for the given file path.

    - Counts lines in binary using chunked reads (memory efficient).
    - Uses os.path.getsize() to get file size in bytes.
    - Raises FileNotFoundError if the path doesn't exist.
    """
    import os

    # Get file size (raises FileNotFoundError if missing)
    size = os.path.getsize(path)

    # Count b'\n' occurrences in chunks
    lines = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            lines += chunk.count(b"\n")

    # If file is non-empty and last byte is not '\n', add the last line
    if size > 0:
        with open(path, "rb") as f:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                lines += 1

    return lines, size


def test_full_trace():
    bug_reproduction = parse_bug_reproduction(
        "/vagrant/artifact_evaluation/tracing_overhead/trace_size/full_trace.yaml"
    )
    print("Running faultless schedule")
    run_reproduction(bug_reproduction.schedule)
    trace_location = collect_history(
        bug_reproduction.trace_location,
        bug_reproduction.result_folder,
        "full_trace",
    )
    run_cleanup(bug_reproduction.cleanup)

    print("Parsing faultless schedule located at " + trace_location)
    history = History()
    history.parse_schedule(bug_reproduction.schedule)
    start_time = time.time()

    history.process_history(trace_location)
    history.discover_faults(None)

    end_time = time.time()
    elapsed_time = end_time - start_time

    lines, size = get_file_stats(trace_location)

    bpf = run_collect_bpf_logs_script(timeout=20)
    bpf_log_path = bpf["output_path"]
    reset_appears_count = count_reset_appears(bpf_log_path)
    if reset_appears_count == 0:
        reset_appears_count = 1
    events = lines * reset_appears_count

    out_path = os.path.join(os.path.dirname(__file__), "/shared/trace_size_results.csv")
    write_header = not os.path.exists(out_path)
    with open(out_path, "a", encoding="utf-8") as f:
        if write_header:
            f.write("tracer,events,lines,size_bytes,elapsed_time_s\n")
        f.write(f"full_trace,{events},{lines},{size},{elapsed_time}\n")


def test_io_trace():
    bug_reproduction = parse_bug_reproduction(
        "/vagrant/artifact_evaluation/tracing_overhead/trace_size/io_trace.yaml"
    )
    print("Running faultless schedule")
    run_reproduction(bug_reproduction.schedule)
    trace_location = collect_history(
        bug_reproduction.trace_location,
        bug_reproduction.result_folder,
        "io_trace",
    )
    run_cleanup(bug_reproduction.cleanup)

    print("Parsing faultless schedule located at " + trace_location)
    history = History()
    history.parse_schedule(bug_reproduction.schedule)
    start_time = time.time()

    history.process_history(trace_location)
    history.discover_faults(None)

    end_time = time.time()
    elapsed_time = end_time - start_time

    lines, size = get_file_stats(trace_location)

    bpf = run_collect_bpf_logs_script(timeout=20)
    bpf_log_path = bpf["output_path"]
    reset_appears_count = count_reset_appears(bpf_log_path)
    if reset_appears_count == 0:
        reset_appears_count = 1
    events = lines * reset_appears_count

    out_path = os.path.join(os.path.dirname(__file__), "/shared/trace_size_results.csv")
    write_header = not os.path.exists(out_path)
    with open(out_path, "a", encoding="utf-8") as f:
        if write_header:
            f.write("tracer,events,lines,size_bytes,elapsed_time_s\n")
        f.write(f"io_trace,{events},{lines},{size},{elapsed_time}\n")


def test_production_trace():
    bug_reproduction = parse_bug_reproduction(
        "/vagrant/artifact_evaluation/tracing_overhead/trace_size/production_trace.yaml"
    )
    print("Running faultless schedule")
    run_reproduction(bug_reproduction.schedule)
    trace_location = collect_history(
        bug_reproduction.trace_location,
        bug_reproduction.result_folder,
        "production_trace",
    )
    run_cleanup(bug_reproduction.cleanup)

    print("Parsing faultless schedule located at " + trace_location)
    history = History()
    history.parse_schedule(bug_reproduction.schedule)
    start_time = time.time()

    history.process_history(trace_location)
    history.discover_faults(None)

    end_time = time.time()
    elapsed_time = end_time - start_time

    lines, size = get_file_stats(trace_location)

    bpf = run_collect_bpf_logs_script(timeout=20)
    bpf_log_path = bpf["output_path"]
    reset_appears_count = count_reset_appears(bpf_log_path)
    if reset_appears_count == 0:
        reset_appears_count = 1
    events = lines * reset_appears_count

    out_path = os.path.join(os.path.dirname(__file__), "/shared/trace_size_results.csv")
    write_header = not os.path.exists(out_path)
    with open(out_path, "a", encoding="utf-8") as f:
        if write_header:
            f.write("tracer,events,lines,size_bytes,elapsed_time_s\n")
        f.write(f"production_trace,{events},{lines},{size},{elapsed_time}\n")


def main():
    print("Running Tests for Section 6.3 Tracer Overhead - Trace Size")
    test_full_trace()
    test_io_trace()
    test_production_trace()


if __name__ == "__main__":
    main()
