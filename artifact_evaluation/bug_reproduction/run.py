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


def main():
    files = read_lines(
        "/vagrant/artifact_evaluation/bug_reproduction/bug_reproductions.txt"
    )

    out_path = "results.txt"
    with open(out_path, "w", encoding="utf-8") as out:
        out.write("bug_reproduction\treplay_rate\truns\telapsed_time_sec\tschedule\n")

        for file in files:
            try:
                # (replay_rate, runs, elapsed_time, schedule)
                replay_rate, runs, elapsed_time, schedule = reproduce_bug(file)

                out.write(
                    f"{file}\t{replay_rate}\t{runs}\t{elapsed_time}\t{schedule}\n"
                )
                move_file("temp_sched.yaml", "results/reproduced_schedule_" + file)
            except Exception as e:
                # Keep going, but record the failure for this entry.
                out.write(f"{file}\tERROR\tERROR\tERROR\t{type(e).__name__}: {e}\n")


if __name__ == "__main__":
    main()
