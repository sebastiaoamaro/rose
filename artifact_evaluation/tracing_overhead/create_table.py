#!/usr/bin/env python3
import csv
import sys
from pathlib import Path


def sniff_dialect(path: Path):
    sample = path.read_text(errors="replace")[:4096]
    # Prefer explicit pipes if present in header
    first_line = sample.splitlines()[0] if sample.splitlines() else ""
    if "|" in first_line and "," not in first_line:
        return "pipe"
    try:
        d = csv.Sniffer().sniff(sample, delimiters=[",", "\t", ";", "|"])
        return d
    except Exception:
        return csv.excel  # default comma


def read_table(path: Path):
    dialect = sniff_dialect(path)
    rows = []
    with path.open(newline="", errors="replace") as f:
        if dialect == "pipe":
            # Treat as pretty table: col1 | col2 | ...
            # We'll split on '|' and strip.
            lines = [ln for ln in f.read().splitlines() if ln.strip()]

            # skip separator lines containing only dashes/plus signs
            def is_sep(ln):
                s = ln.strip()
                return s and all(c in "-+|" or c.isspace() for c in s)

            lines = [ln for ln in lines if not is_sep(ln)]
            header = [h.strip() for h in lines[0].split("|")]
            for ln in lines[1:]:
                vals = [v.strip() for v in ln.split("|")]
                # pad/truncate
                vals = (vals + [""] * len(header))[: len(header)]
                rows.append(dict(zip(header, vals)))
            return rows

        reader = csv.DictReader(f, dialect=dialect)
        for r in reader:
            # strip whitespace from keys and values
            clean = {}
            for k, v in r.items():
                if k is None:
                    continue
                kk = k.strip()
                vv = v.strip() if isinstance(v, str) else v
                clean[kk] = vv
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

    overhead_path = Path("/shared/throughtput_overhead.txt")
    stats_path = Path("/shared/trace_size_results.csv")

    overhead_rows = read_table(overhead_path)
    stats_rows = read_table(stats_path)

    # normalize overhead map
    overhead_by_tracer = {}
    for r in overhead_rows:
        tracer = pick(r, "tracer", "Tracer").strip()
        overhead = pick(r, "overhead_%", "overhead", "Overhead", "overhead%").strip()
        if tracer:
            overhead_by_tracer[tracer] = overhead

    # sanity check
    if stats_rows and not any(pick(r, "tracer", "Tracer").strip() for r in stats_rows):
        print(
            "Error: couldn't find non-empty 'tracer' values in stats file.",
            file=sys.stderr,
        )
        print(f"Detected stats headers: {list(stats_rows[0].keys())}", file=sys.stderr)
        sys.exit(1)

    merged = []
    for r in stats_rows:
        tracer = pick(r, "tracer", "Tracer").strip()
        merged.append(
            {
                "tracer": tracer,
                "overhead_%": overhead_by_tracer.get(tracer, ""),
                "events": pick(r, "events", "Events"),
                "lines": pick(r, "lines", "Lines"),
                "size_bytes": pick(r, "size_bytes", "size", "bytes", "SizeBytes"),
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
        "size_bytes",
        "elapsed_time_s",
    ]

    # format and compute widths
    formatted = []
    widths = {h: len(h) for h in headers}
    for row in merged:
        fr = {
            "tracer": row["tracer"],
            "overhead_%": row["overhead_%"],
            "events": fmt_int(row["events"]),
            "lines": fmt_int(row["lines"]),
            "size_bytes": fmt_int(row["size_bytes"]),
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
                fr["size_bytes"].rjust(widths["size_bytes"]),
                fr["elapsed_time_s"].rjust(widths["elapsed_time_s"]),
            ]
        )

    sep = "-+-".join("-" * widths[h] for h in headers)

    print(render({h: h for h in headers}))
    print(sep)
    for fr in formatted:
        print(render(fr))


if __name__ == "__main__":
    main()
