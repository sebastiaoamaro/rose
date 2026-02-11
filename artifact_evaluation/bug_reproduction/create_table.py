import os
import sys
from dataclasses import dataclass
from typing import Iterable

EXPECTED_COLS = [
    "bug_reproduction",
    "replay_rate",
    "runs",
    "elapsed_time_sec",
    "schedule",
    "fault_removal_pct",
]

FIXED_INPUTS = [
    "/shared/",
    "/shared/",
    "/shared/",
]


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
            "bug_reproduction": self.bug_reproduction,
            "replay_rate": self.replay_rate,
            "runs": self.runs,
            "schedules_generated": self.schedules_generated,
            "elapsed_time_sec": self.elapsed_time_sec,
            "schedule": self.schedule,
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


def _parse_row(line: str, *, source_path: str, line_no: int) -> Row | None:
    parts = line.split("\t")
    if len(parts) != 6:
        # Be forgiving: ignore malformed lines (e.g., the ERROR lines in run.py have 5 cols).
        return None

    return Row(
        bug_reproduction=parts[0].strip(),
        replay_rate=parts[1].strip(),
        runs=parts[2].strip(),
        schedules_generated=parts[3].strip(),
        elapsed_time_sec=parts[4].strip(),
        schedule=parts[5].strip(),
        fault_removal_pct=parts[6].strip(),
    )


def _read_rows(path: str) -> list[Row]:
    rows: list[Row] = []
    for i, line in enumerate(_iter_data_lines(path), start=1):
        row = _parse_row(line, source_path=path, line_no=i)
        if row is None:
            continue
        rows.append(row)
    return rows


def _render_table(rows: list[Row]) -> str:
    dict_rows = [r.as_dict() for r in rows]

    widths = {h: len(h) for h in EXPECTED_COLS}
    for r in dict_rows:
        for h in EXPECTED_COLS:
            widths[h] = max(widths[h], len(r[h]))

    def render_row(r: dict[str, str]) -> str:
        # Left-align paths/strings, right-align numeric-ish fields for readability.
        cells: list[str] = []
        for h in EXPECTED_COLS:
            v = r[h]
            if h in ("bug_reproduction", "schedule"):
                cells.append(v.ljust(widths[h]))
            else:
                cells.append(v.rjust(widths[h]))
        return " | ".join(cells)

    header = render_row({h: h for h in EXPECTED_COLS})
    sep = "-+-".join("-" * widths[h] for h in EXPECTED_COLS)

    out_lines = [header, sep]
    for r in dict_rows:
        out_lines.append(render_row(r))
    return "\n".join(out_lines)


def main() -> int:
    missing = [p for p in FIXED_INPUTS if not os.path.exists(p)]
    if missing:
        print("Missing expected input file(s):", file=sys.stderr)
        for p in missing:
            print(f"  - {p}", file=sys.stderr)
        print(
            "\nGenerate them by running `run.py` to produce results files under "
            "`/vagrant/artifact_evaluation/bug_reproduction/results/`.",
            file=sys.stderr,
        )
        return 2

    all_rows: list[Row] = []
    for p in FIXED_INPUTS:
        all_rows.extend(_read_rows(p))

    # Sort by bug_reproduction (as requested), then schedule, then replay_rate/runs/time (string sort)
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
    raise SystemExit(main())
