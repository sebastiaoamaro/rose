import os
import selectors
import subprocess
import time

from analyzer.trace_analysis import calculate_faults_removed
from reproduction import (
    History,
    collect_history,
    parse_bug_reproduction,
    run_cleanup,
    run_reproduction,
)


def get_faults_removed_stats(bug_specification):
    print(bug_specification)
    bug_reproduction = parse_bug_reproduction(bug_specification)
    print("Running faultless schedule")
    run_reproduction(bug_reproduction.schedule)
    trace_location = collect_history(
        bug_reproduction.trace_location, bug_reproduction.result_folder, "normal"
    )
    run_cleanup(bug_reproduction.cleanup)

    # Parse faultless schedule
    print("Parsing faultless schedule located at " + trace_location)
    history = History()
    history.parse_schedule(bug_reproduction.schedule)
    history.process_history(trace_location)
    faults_normal = history.discover_faults(None)

    # Parse buggy trace
    print("Parsing buggy trace located at " + bug_reproduction.buggy_trace)
    history_buggy = History()
    history_buggy.parse_schedule(bug_reproduction.schedule)
    history_buggy.process_history(bug_reproduction.buggy_trace)
    faults_buggy = history_buggy.discover_faults(history)
    history_buggy.write_to_file("/tmp/parsed_buggy_history.txt")
    statistics = calculate_faults_removed(faults_buggy, faults_normal)
    print(statistics)


def read_lines(file_path: str) -> list[str]:
    """
    Read newline-separated entries from `file_path`.

    - Strips surrounding whitespace
    - Skips empty lines
    - Skips comment lines starting with '#'
    """
    lines: list[str] = []
    with open(file_path, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            lines.append(line)
    return lines


def main():
    files = read_lines(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/faults_removed/bug_reproductions.txt"
    )
    for file in files:
        get_faults_removed_stats(file)


if __name__ == "__main__":
    main()
