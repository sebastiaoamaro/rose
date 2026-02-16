import os
import selectors
import subprocess
import time

from reproduction import (
    History,
    move_file,
    run_reproduction,
)


def run_schedules_normal():
    run_reproduction(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/normal_schedules/redpanda_3003.yaml"
    )
    collect_statistics("normal_redpanda_3003_stats.txt")

    run_reproduction(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/normal_schedules/rr_43.yaml"
    )
    collect_statistics("normal_rr_43_stats.txt")
    run_reproduction(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/normal_schedules/rr_51.yaml"
    )
    collect_statistics("normal_rr_51_stats.txt")
    run_reproduction(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/normal_schedules/rr_nr.yaml"
    )
    collect_statistics("normal_rr_nr_stats.txt")


def run_schedules_no_heuristic():
    run_reproduction(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/no_heuristic_schedules/redpanda_3003.yaml"
    )
    collect_statistics("no_heuristic_redpanda_3003_stats.txt")
    run_reproduction(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/no_heuristic_schedules/rr_43.yaml"
    )
    collect_statistics("no_heuristic_rr_43_stats.txt")
    run_reproduction(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/no_heuristic_schedules/rr_51.yaml"
    )
    collect_statistics("no_heuristic_rr_51_stats.txt")
    run_reproduction(
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/no_heuristic_schedules/rr_nr.yaml"
    )
    collect_statistics("no_heuristic_rr_nr_stats.txt")


def collect_statistics(schedule_name):
    move_file(
        "/tmp/function_stats.txt",
        "/shared/" + schedule_name,
    )


def _parse_total_calls(stats_file: str) -> int:
    """
    Each line is: function_name, offset, number_of_calls
    We compare the *total number of calls* => sum(number_of_calls).
    """
    total = 0
    with open(stats_file, "r") as f:
        for line_no, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3:
                raise ValueError(
                    f"Malformed line in {stats_file}:{line_no} (expected 3 comma-separated fields): {raw!r}"
                )

            try:
                calls = int(parts[2])
            except ValueError as e:
                raise ValueError(
                    f"Invalid call count in {stats_file}:{line_no} (field 3): {parts[2]!r}"
                ) from e

            total += calls

    return total


def compare_values():
    print("Comparing function statistics (total call counts)")

    results_dir = os.path.join(os.path.dirname(__file__), "/shared/")
    if not os.path.isdir(results_dir):
        print(f"Results directory not found: {results_dir}")
        return

    entries = sorted(os.listdir(results_dir))
    normal_files = [
        n for n in entries if n.startswith("normal_") and n.endswith(".txt")
    ]
    no_heur_files = [
        n for n in entries if n.startswith("no_heuristic_") and n.endswith(".txt")
    ]

    def key_from_normal(filename: str) -> str:
        return filename[len("normal_") : -len(".txt")]

    def key_from_no_heur(filename: str) -> str:
        return filename[len("no_heuristic_") : -len(".txt")]

    normal_by_key = {key_from_normal(n): n for n in normal_files}
    no_heur_by_key = {key_from_no_heur(n): n for n in no_heur_files}

    shared_keys = sorted(set(normal_by_key.keys()) & set(no_heur_by_key.keys()))
    if not shared_keys:
        print(
            f"No normal/no_heuristic pairs found in {results_dir}. "
            f"Expected files like normal_X.txt and no_heuristic_X.txt"
        )
        return

    rows = []
    for key in shared_keys:
        normal_path = os.path.join(results_dir, normal_by_key[key])
        no_heur_path = os.path.join(results_dir, no_heur_by_key[key])

        normal_total = _parse_total_calls(normal_path)
        no_heur_total = _parse_total_calls(no_heur_path)

        pct = (
            ((normal_total - no_heur_total) / no_heur_total * 100.0)
            if no_heur_total != 0
            else None
        )

        rows.append(
            {
                "case": key,
                "normal": str(normal_total),
                "no_heuristic": str(no_heur_total),
                "%diff": "N/A" if pct is None else f"{pct:+.2f}%",
            }
        )

    headers = ["case", "normal", "no_heuristic", "%diff"]
    widths = {
        h: max(len(h), *(len(r[h]) for r in rows)) if rows else len(h) for h in headers
    }

    def sep(char: str = "-") -> str:
        return "+" + "+".join(char * (widths[h] + 2) for h in headers) + "+"

    def fmt_row(values: dict) -> str:
        parts = []
        for h in headers:
            v = values[h]
            if h in ("normal", "no_heuristic", "%diff"):
                parts.append(" " + v.rjust(widths[h]) + " ")
            else:
                parts.append(" " + v.ljust(widths[h]) + " ")
        return "|" + "|".join(parts) + "|"

    out_path = os.path.join(results_dir, "heuristics_table.txt")
    with open(out_path, "w", encoding="utf-8") as out:
        out.write(sep("-") + "\n")
        out.write(fmt_row({h: h for h in headers}) + "\n")
        out.write(sep("=") + "\n")
        for r in rows:
            out.write(fmt_row(r) + "\n")
        out.write(sep("-") + "\n")

    print(f"Wrote final table to: {out_path}")


def main():
    print("Running Tests for Section 6.4 Heuristic Effectiveness - Frequent Functions")
    run_schedules_normal()
    run_schedules_no_heuristic()
    compare_values()


if __name__ == "__main__":
    main()
