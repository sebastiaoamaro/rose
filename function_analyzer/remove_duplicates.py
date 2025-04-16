import sys

def remove_duplicates(input_file, output_file):
    seen = set()
    unique_lines = []

    with open(input_file, 'r') as f:
        for line in f:
            if line not in seen:
                seen.add(line)
                unique_lines.append(line)

    with open(output_file, 'w') as f:
        f.writelines(unique_lines)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python remove_duplicates.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    remove_duplicates(input_file, output_file)
    print(f"Duplicate-free file saved to: {output_file}")
