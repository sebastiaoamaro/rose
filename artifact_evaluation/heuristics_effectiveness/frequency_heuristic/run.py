import os
import selectors
import subprocess
import time

from reproduction import (
    History,
    collect_history,
    move_file,
    parse_bug_reproduction,
    run_cleanup,
    run_reproduction,
    save_schedule,
    write_new_schedule,
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
        "/vagrant/artifact_evaluation/heuristics_effectiveness/frequency_heuristic/results/"
        + schedule_name,
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

    results_dir = os.path.join(os.path.dirname(__file__), "results")
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

    grand_normal = 0
    grand_no_heur = 0

    for key in shared_keys:
        normal_path = os.path.join(results_dir, normal_by_key[key])
        no_heur_path = os.path.join(results_dir, no_heur_by_key[key])

        normal_total = _parse_total_calls(normal_path)
        no_heur_total = _parse_total_calls(no_heur_path)

        grand_normal += normal_total
        grand_no_heur += no_heur_total

        diff = normal_total - no_heur_total
        pct = (diff / no_heur_total * 100.0) if no_heur_total != 0 else None

        print(f"\nCase: {key}")
        print(f"  normal:       {normal_total}")
        print(f"  no_heuristic: {no_heur_total}")
        print(f"  diff:         {diff}")
        if pct is None:
            print("  diff(%):      N/A (no_heuristic total is 0)")
        else:
            print(f"  diff(%):      {pct:.2f}%")


def main():
    print("Running Tests for Section 6.4 Heuristic Effectiveness - Frequent Functions")

    run_schedules_normal()
    run_schedules_no_heuristic()
    compare_values()


if __name__ == "__main__":
    main()
