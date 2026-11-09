#!/bin/bash
# Compiles every *.c test program in this directory to a same-named binary
# next to it (partial_write_demo.c -> partial_write_demo).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

CC=${CC:-gcc}

shopt -s nullglob
sources=(*.c)
shopt -u nullglob

if [ ${#sources[@]} -eq 0 ]; then
    echo "No .c files found in $(pwd)"
    exit 0
fi

for src in "${sources[@]}"; do
    bin="${src%.c}"
    echo "Building $bin from $src..."
    "$CC" -O0 -Wall -o "$bin" "$src"
done

echo "Done."
