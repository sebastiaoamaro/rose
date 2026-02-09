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
        print("Usage: python run.py <bugs_file> [times]", file=sys.stderr)
        raise SystemExit(1)

    bugs_file = sys.argv[1]
    times = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    files = read_lines(bugs_file)

    # Per-file aggregates across successful runs only
    per_file = defaultdict(
        lambda: {"success": 0, "replay_rate": 0.0, "runs": 0.0, "elapsed_time_sec": 0.0}
    )

    out_path = "results.txt"
    with open(out_path, "w", encoding="utf-8") as out:
        out.write("bug_reproduction\treplay_rate\truns\telapsed_time_sec\tschedule\n")

        for file in files:
            for _ in range(times):
                try:
                    # (replay_rate, runs, elapsed_time, schedule)
                    replay_rate, runs, elapsed_time, schedule = reproduce_bug(file)

                    out.write(
                        f"{file}\t{replay_rate}\t{runs}\t{elapsed_time}\t{schedule}\n"
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

                    move_file(
                        "/tmp/temp_sched.yaml",
                        "/vagrant/artifact_evaluation/bug_reproduction/results/reproduced_schedule_"
                        + file,
                    )
                except Exception as e:
                    out.write(f"{file}\tERROR\tERROR\tERROR\t{type(e).__name__}: {e}\n")

        out.write("\n")
        out.write(
            "# per_file_avg (bug\tsuccesses\tavg_replay_rate\tavg_runs\tavg_elapsed_time_sec)\n"
        )
        for bug, agg in sorted(per_file.items(), key=lambda kv: kv[0]):
            n = agg["success"]
            if n == 0:
                out.write(f"# {bug}\t0\tERROR\tERROR\tERROR\n")
                continue
            out.write(
                f"# {bug}\t{n}\t"
                f"{agg['replay_rate'] / n}\t"
                f"{agg['runs'] / n}\t"
                f"{agg['elapsed_time_sec'] / n}\n"
            )


if __name__ == "__main__":
    main()
