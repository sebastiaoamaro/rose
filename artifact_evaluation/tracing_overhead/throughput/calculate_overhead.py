import os
import re
import sys
from collections import defaultdict


def process_directory(directory):
    category_data = defaultdict(list)

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)

        if os.path.isdir(file_path) or "history_" in filename:
            continue

        try:
            category = filename.split(":", 1)[0]
            print(category)
        except IndexError:
            continue

        try:
            with open(file_path, "r") as f:
                for line in f:
                    if line.startswith("[OVERALL], Throughput(ops/sec),"):
                        throughput = float(line.split(", ")[2].strip())
                        category_data[category].append(throughput)
                        break
        except Exception as e:
            print(f"Error processing {filename}: {str(e)}", file=sys.stderr)

    averages = {
        cat: sum(vals) / len(vals) for cat, vals in category_data.items() if vals
    }
    return averages


def calculate_percentage_differences(averages):
    # Group categories by their numeric suffix (3 or 6)
    groups = defaultdict(dict)
    for cat, avg in averages.items():
        match = re.search(r"(\d+)$", cat)
        if match:
            group = match.group(1)
            groups[group][cat] = avg

    results = []
    for group, group_averages in groups.items():
        # Find baseline (topology{group})
        baseline_name = f"vanilla{group}"
        baseline = group_averages.get(baseline_name)

        if baseline is None or baseline == 0:
            print(
                f"Warning: No valid baseline found for group {group}", file=sys.stderr
            )
            continue

        for category, avg in group_averages.items():
            if category == baseline_name:
                continue  # Skip baseline itself
            percentage_diff = ((avg - baseline) / baseline) * 100
            results.append(
                (group, category, avg, baseline_name, baseline, percentage_diff)
            )

    return results


def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a valid directory")
        sys.exit(1)

    averages = process_directory(directory)
    results = calculate_percentage_differences(averages)

    print("tracer,overhead_%")
    for group, category, avg, base_name, base_val, pct in sorted(
        results, key=lambda x: (x[0], x[1])
    ):
        print(f"{category},{pct / 3:+.2f}")


if __name__ == "__main__":
    main()
