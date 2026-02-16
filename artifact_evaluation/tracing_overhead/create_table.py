#!/usr/bin/env python3
import csv
import os
import sys
from pathlib import Path


def fmt_int(x):
    try:
        return f"{int(float(x))}"
    except Exception:
        return str(x) if x is not None else ""


def fmt_mb_from_bytes(x, nd=2):
    try:
        b = float(x)
        return f"{b / (1024 * 1024):.{nd}f}"
    except Exception:
        return str(x) if x is not None else ""


def sniff_dialect(path: Path):
    sample = path.read_text(errors="replace")[:4096]
    lines = [ln for ln in sample.splitlines() if ln.strip()]

    # Only treat as "pipe table" if we actually see pipe-separated rows
    # (i.e., at least 2 lines containing a '|').
    pipe_lines = [ln for ln in lines if "|" in ln]
    if len(pipe_lines) >= 2:
        return "pipe"

    try:
        return csv.Sniffer().sniff(sample, delimiters=[",", "\t", ";"])
    except Exception:
        return csv.excel  # default comma


def read_table(path: Path):
    dialect = sniff_dialect(path)
    rows = []
    with path.open(newline="", errors="replace") as f:
        if dialect == "pipe":
            lines = [ln for ln in f.read().splitlines() if ln.strip()]

            def is_sep(ln: str) -> bool:
                s = ln.strip()
                return s and all(c in "-+|" or c.isspace() for c in s)

            lines = [ln for ln in lines if not is_sep(ln)]
            header = [h.strip() for h in lines[0].split("|")]
            for ln in lines[1:]:
                vals = [v.strip() for v in ln.split("|")]
                vals = (vals + [""] * len(header))[: len(header)]
                rows.append(dict(zip(header, vals)))
            return rows

        reader = csv.DictReader(f, dialect=dialect)
        for r in reader:
            clean = {}
            for k, v in r.items():
                if k is None:
                    continue
                clean[k.strip()] = v.strip() if isinstance(v, str) else v
            rows.append(clean)
        return rows


def pick(row, *keys):
    for k in keys:
        if k in row:
            return row[k]
    return ""


def fmt_int(x):
    try:
        return f"{int(float(x))}"
    except Exception:
        return str(x) if x is not None else ""


def fmt_float(x, nd=2):
    try:
        return f"{float(x):.{nd}f}"
    except Exception:
        return str(x) if x is not None else ""


def main():
    base_dir = Path("~/shared/test3").expanduser()
    overhead_path = base_dir / "throughtput_overhead.txt"
    stats_path = base_dir / "trace_size_results.csv"
    out_path = base_dir / "trace_overhead_table.txt"

    overhead_rows = read_table(overhead_path)
    stats_rows = read_table(stats_path)

    # normalize overhead map
    # Build overhead map (keyed by tracer)
    overhead_by_tracer = {}
    for r in overhead_rows:
        tracer = pick(r, "tracer", "Tracer").strip()
        overhead = pick(r, "overhead_%", "overhead", "Overhead", "overhead%").strip()
        if tracer:
            overhead_by_tracer[tracer] = overhead

    merged = []
    missing_overhead = []
    for r in stats_rows:
        tracer = pick(r, "tracer", "Tracer").strip()
        overhead_val = overhead_by_tracer.get(tracer, "")
        if tracer and overhead_val == "":
            missing_overhead.append(tracer)

        merged.append(
            {
                "tracer": tracer,
                "overhead_%": overhead_val,
                "events": pick(r, "events", "Events"),
                "lines": pick(r, "lines", "Lines"),
                "size_mb": pick(r, "size_bytes", "size", "bytes", "SizeBytes"),
                "elapsed_time_s": pick(
                    r, "elapsed_time_s", "elapsed", "time_s", "ElapsedTimeS"
                ),
            }
        )

    merged.sort(key=lambda x: x["tracer"])

    headers = [
        "tracer",
        "overhead_%",
        "events",
        "lines",
        "size_mb",
        "elapsed_time_s",
    ]

    formatted = []
    widths = {h: len(h) for h in headers}
    for row in merged:
        fr = {
            "tracer": row["tracer"],
            "overhead_%": row["overhead_%"],
            "events": fmt_int(row["events"]),
            "lines": fmt_int(row["lines"]),
            "size_mb": fmt_mb_from_bytes(row["size_mb"], 2),
            "elapsed_time_s": fmt_float(row["elapsed_time_s"], 2),
        }
        formatted.append(fr)
        for h in headers:
            widths[h] = max(widths[h], len(fr[h]))

    def render(fr):
        return " | ".join(
            [
                fr["tracer"].ljust(widths["tracer"]),
                fr["overhead_%"].rjust(widths["overhead_%"]),
                fr["events"].rjust(widths["events"]),
                fr["lines"].rjust(widths["lines"]),
                fr["size_mb"].rjust(widths["size_mb"]),
                fr["elapsed_time_s"].rjust(widths["elapsed_time_s"]),
            ]
        )

    sep = "-+-".join("-" * widths[h] for h in headers)

    lines = []
    lines.append(render({h: h for h in headers}))
    lines.append(sep)
    for fr in formatted:
        lines.append(render(fr))

    table = "\n".join(lines) + "\n"

    # Print to terminal
    print(table, end="")

    # Write to file
    out_path.write_text(table)
    print(f"Wrote table to: {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
