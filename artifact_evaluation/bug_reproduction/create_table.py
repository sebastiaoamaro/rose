import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass

# Internal column keys (must match Row.as_dict()) in the order they should be displayed.
COLS = [
    "bug_reproduction",
    "replay_rate",
    "runs",
    "schedules_generated",
    "elapsed_time_sec",
    "schedule",
    "fault_removal_pct",
]

# Display names (change these to rename columns in the output table).
COL_LABELS: dict[str, str] = {
    "bug_reproduction": "bug",
    "replay_rate": "RR%",
    "runs": "#R",
    "schedules_generated": "Sched",
    "elapsed_time_sec": "T(m)",
    "schedule": "schedule",
    "fault_removal_pct": "FR(%)",
}

# Default inputs if none are provided via CLI.
FIXED_INPUTS = [
    "~/shared/test1/results_scf_bugs.txt",
    # "~/shared/test1/results_zk_4203.txt",
    # "/shared/test2/results_docker_bugs.txt",
    # "/shared/test3/results_lxc_bugs.txt",
]


def _base(p: str) -> str:
    p = (p or "").strip()
    return os.path.basename(p) if p else ""


def _norm_path(p: str) -> str:
    # Expand "~" (shell-style home) and environment variables.
    return os.path.expandvars(os.path.expanduser(p))


@dataclass(frozen=True)
class Row:
    bug_reproduction: str
    replay_rate: str
    runs: str
    schedules_generated: str
    elapsed_time_sec: str
    schedule: str
    fault_removal_pct: str

    def as_dict(self) -> dict[str, str]:
        return {
            "bug_reproduction": _base(self.bug_reproduction),
            "replay_rate": self.replay_rate,
            "runs": self.runs,
            "schedules_generated": self.schedules_generated,
            "elapsed_time_sec": self.elapsed_time_sec,
            "schedule": _base(self.schedule),
            "fault_removal_pct": self.fault_removal_pct,
        }


def _iter_data_lines(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            if line.lstrip().startswith("#"):
                continue
            yield line


def _parse_row(line: str) -> Row | None:
    """
    Supports:
      - success lines from run.py (7 tab-separated columns)
      - error lines from run.py (5 tab-separated columns):
          <file>  ERROR  ERROR  ERROR  <message>
        These will be kept and padded with placeholders so they show up in the table.
    """
    parts = [p.strip() for p in line.split("\t")]

    # Success line (expected)
    if len(parts) == 7:
        return Row(
            bug_reproduction=parts[0],
            replay_rate=parts[1],
            runs=parts[2],
            schedules_generated=parts[3],
            elapsed_time_sec=parts[4],
            schedule=parts[5],
            fault_removal_pct=parts[6],
        )

    # Error line written by run.py
    if len(parts) == 5 and len(parts) >= 2 and parts[1] == "ERROR":
        return Row(
            bug_reproduction=parts[0],
            replay_rate="ERROR",
            runs="ERROR",
            schedules_generated="ERROR",
            elapsed_time_sec=parts[4],  # contains the exception message
            schedule="",
            fault_removal_pct="",
        )

    # Unknown/malformed line
    return None


def _read_rows(path: str) -> list[Row]:
    rows: list[Row] = []
    for line in _iter_data_lines(path):
        row = _parse_row(line)
        if row is not None:
            rows.append(row)
    return rows


def _render_table(rows: list[Row]) -> str:
    dict_rows = [r.as_dict() for r in rows]

    # Use display labels for the header width, and data widths for the content.
    widths = {k: len(COL_LABELS.get(k, k)) for k in COLS}
    for r in dict_rows:
        for k in COLS:
            widths[k] = max(widths[k], len(r[k]))

    def render_row(r: dict[str, str]) -> str:
        cells: list[str] = []
        for k in COLS:
            v = r[k]
            # Left-align paths/strings, right-align numeric-ish fields for readability.
            if k in ("bug_reproduction", "schedule"):
                cells.append(v.ljust(widths[k]))
            else:
                cells.append(v.rjust(widths[k]))
        return " | ".join(cells)

    header = render_row({k: COL_LABELS.get(k, k) for k in COLS})
    sep = "-+-".join("-" * widths[k] for k in COLS)

    out_lines = [header, sep]
    for r in dict_rows:
        out_lines.append(render_row(r))
    return "\n".join(out_lines)


def main(argv: list[str]) -> int:
    raw_inputs = argv[1:] if len(argv) > 1 else FIXED_INPUTS
    input_paths = [_norm_path(p) for p in raw_inputs]

    missing = [p for p in input_paths if not os.path.exists(p)]
    if missing:
        print("Missing expected input file(s):", file=sys.stderr)
        for p in missing:
            print(f"  - {p}", file=sys.stderr)
        print(
            "\nGenerate them by running `run.py` to produce results files under "
            "`/shared/results_<bugs_file>` (inside the VM), then point this script at that file.",
            file=sys.stderr,
        )
        return 2

    all_rows: list[Row] = []
    for p in input_paths:
        all_rows.extend(_read_rows(p))

    # Sort by bug_reproduction, then schedule, then other fields (string sort).
    all_rows.sort(
        key=lambda r: (
            r.bug_reproduction,
            r.schedule,
            r.replay_rate,
            r.runs,
            r.schedules_generated,
            r.elapsed_time_sec,
            r.fault_removal_pct,
        )
    )

    print(_render_table(all_rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
