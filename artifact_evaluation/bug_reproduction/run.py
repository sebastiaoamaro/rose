import os
import sys
from collections import defaultdict

from reproduction import move_file, reproduce_bug


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


def _safe_float(x) -> float | None:
    try:
        return float(x)
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python run.py <bugs_file>", file=sys.stderr)
        return

    print("Starting reproducing bugs in file:", sys.argv[1])
    bugs_file = sys.argv[1]

    entries = read_lines(bugs_file)

    files: list[str] = []
    times_by_file: dict[str, int] = {}

    for entry in entries:
        parts = entry.split()
        if not parts:
            continue

        if len(parts) > 2:
            raise ValueError(
                f"Invalid line in {bugs_file!r}: {entry!r}. Expected: '<bug_file> [times]'"
            )

        bug_file = parts[0]
        times = int(parts[1]) if len(parts) == 2 else 1

        files.append(bug_file)
        times_by_file[bug_file] = times

    total_runs = sum(times_by_file[f] for f in files)

    # Per-file aggregates across successful runs only
    per_file = defaultdict(
        lambda: {"success": 0, "replay_rate": 0.0, "runs": 0.0, "elapsed_time_sec": 0.0}
    )

    out_path = "/shared/results_" + bugs_file
    write_header = not os.path.exists(out_path)
    with open(out_path, "w", encoding="utf-8") as out:
        for file in files:
            t = times_by_file.get(file, 1)
            print(f"Reproducing bug from file: {file} (times={t})")
            sucess_count = 0
            while sucess_count != t:
                try:
                    (
                        replay_rate,
                        runs,
                        schedules_generated,
                        elapsed_time,
                        schedule,
                        fault_removal_pct,
                    ) = reproduce_bug(file)

                    if replay_rate >= 60:
                        sucess_count += 1
                    else:
                        continue

                    source = "/tmp/temp_sched.yaml"
                    file_name = os.path.basename(file)
                    destination = "/shared/reproduced_schedule_" + file_name
                    print("Moving schedule from", source, "to", destination)
                    schedule = destination
                    move_file(source, destination)
                    out.write(
                        f"{file}\t{replay_rate}\t{runs}\t{schedules_generated}\t{elapsed_time}\t{schedule}\t{fault_removal_pct}\n"
                    )

                    rr = _safe_float(replay_rate)
                    r = _safe_float(runs)
                    et = _safe_float(elapsed_time)

                    # Aggregate only if all numeric fields are valid
                    if rr is not None and r is not None and et is not None:
                        per_file[file]["success"] += 1
                        per_file[file]["replay_rate"] += rr
                        per_file[file]["runs"] += r
                        per_file[file]["elapsed_time_sec"] += et

                except Exception as e:
                    out.write(f"{file}\tERROR\tERROR\tERROR\t{type(e).__name__}: {e}\n")


if __name__ == "__main__":
    main()
