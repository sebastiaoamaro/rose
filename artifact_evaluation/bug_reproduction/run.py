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
    print(
        f"Read {len(files)} bugs from {bugs_file}, "
        f"will run {total_runs} total reproductions "
        f"(per-bug times specified in file)"
    )

    # Per-file aggregates across successful runs only
    per_file = defaultdict(
        lambda: {"success": 0, "replay_rate": 0.0, "runs": 0.0, "elapsed_time_sec": 0.0}
    )

    out_path = (
        "/vagrant/artifact_evaluation/bug_reproduction/results/results_" + bugs_file
    )
    with open(out_path, "w", encoding="utf-8") as out:
        out.write("bug_reproduction\treplay_rate\truns\telapsed_time_sec\tschedule\n")

        for file in files:
            t = times_by_file.get(file, 1)
            print(f"Reproducing bug from file: {file} (times={t})")
            sucess_count = 0
            while sucess_count != t:
                try:
                    # (replay_rate, runs, elapsed_time, schedule)
                    replay_rate, runs, elapsed_time, schedule = reproduce_bug(file)

                    if replay_rate != 0:
                        sucess_count += 1
                    else:
                        sucess_count += 1

                    source = "/tmp/temp_sched.yaml"
                    file_name = os.path.basename(file)
                    destination = (
                        "/vagrant/artifact_evaluation/bug_reproduction/results/reproduced_schedule_"
                        + file_name
                    )
                    print("Moving schedule from", source, "to", destination)
                    schedule = destination
                    move_file(source, destination)
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

                except Exception as e:
                    out.write(f"{file}\tERROR\tERROR\tERROR\t{type(e).__name__}: {e}\n")

        out.write("\n")
        out.write(
            "# per_file_avg (bug\tsuccesses\tavg_replay_rate\tavg_runs\tavg_elapsed_time_sec)\n"
        )

        # Build rows for pretty-printing + file output
        rows: list[dict[str, str]] = []
        for bug, agg in sorted(per_file.items(), key=lambda kv: kv[0]):
            n = agg["success"]
            if n == 0:
                rr_s, runs_s, et_s = "ERROR", "ERROR", "ERROR"
                out.write(f"# {bug}\t0\tERROR\tERROR\tERROR\n")
            else:
                rr = agg["replay_rate"] / n
                runs = agg["runs"] / n
                et = agg["elapsed_time_sec"] / n
                rr_s, runs_s, et_s = f"{rr:.4f}", f"{runs:.2f}", f"{et:.2f}"
                out.write(f"# {bug}\t{n}\t{rr}\t{runs}\t{et}\n")

            rows.append(
                {
                    "bug": bug,
                    "successes": str(n),
                    "avg_replay_rate": rr_s,
                    "avg_runs": runs_s,
                    "avg_elapsed_time_s": et_s,
                }
            )

        # Pretty-print table to terminal
        headers = [
            "bug",
            "successes",
            "avg_replay_rate",
            "avg_runs",
            "avg_elapsed_time_s",
        ]
        widths = {h: len(h) for h in headers}
        for r in rows:
            for h in headers:
                widths[h] = max(widths[h], len(r[h]))

        def render_row(r: dict[str, str]) -> str:
            return " | ".join(
                [
                    r["bug"].ljust(widths["bug"]),
                    r["successes"].rjust(widths["successes"]),
                    r["avg_replay_rate"].rjust(widths["avg_replay_rate"]),
                    r["avg_runs"].rjust(widths["avg_runs"]),
                    r["avg_elapsed_time_s"].rjust(widths["avg_elapsed_time_s"]),
                ]
            )

        sep = "-+-".join("-" * widths[h] for h in headers)

        print("\nPer-bug averages (successful runs only):")
        print(render_row({h: h for h in headers}))
        print(sep)
        for r in rows:
            print(render_row(r))


if __name__ == "__main__":
    main()
