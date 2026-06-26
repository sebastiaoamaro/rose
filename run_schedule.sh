#!/bin/bash
ROSE_DIR=/vagrant
EXECUTOR_DIR=$ROSE_DIR/executor/c
KERNEL_DIR=$ROSE_DIR/executor/kernelmodule
TMP_FILES=(/tmp/containerpid_read /tmp/containerpid_write /tmp/history.txt /tmp/pid_tree.txt)

silent() { "$@" > /dev/null 2>&1; }

build_module() {
    (cd "$KERNEL_DIR" && make)
    silent sudo rmmod rose || true
    silent sudo insmod "$KERNEL_DIR/rose.ko"
}

clean_tmp() {
    for f in "${TMP_FILES[@]}"; do silent sudo rm -f "$f"; done
}

build_schedule() {
    local schedule=$1
    silent python3 "$ROSE_DIR/parser.py" "$schedule"
    silent mv fault_schedule.c "$EXECUTOR_DIR/"
    make -j"$(nproc)" -C "$EXECUTOR_DIR"
}

run_main() {
    sudo -E "$EXECUTOR_DIR/main/main"
}

# --- Build kernel module once ---
build_module

cd "$ROSE_DIR"

# --- Single run ---
if [[ $# -eq 1 ]]; then
    clean_tmp
    build_schedule "$1"
    run_main
fi

# --- Folder mode: run all schedules in a directory ---
if [[ $# -ge 5 && $1 == folder ]]; then
    dir=$2 output_folder=$3 oracle=$4 cleanup=$5
    for file in "$dir"/*; do
        [[ -f $file ]] || continue
        clean_tmp
        build_schedule "$file"
        run_main
        filename=$(basename "$file")
        silent sudo mv /tmp/history.txt "$output_folder/$filename.txt"
        silent sh "$oracle" "$filename" "$output_folder"
        silent sh "$cleanup"
    done
fi

# --- Runs mode: repeat a single schedule N times ---
if [[ $# -ge 5 && $1 == runs ]]; then
    runs=$2 schedule=$3 output_folder=$4 oracle=$5 cleanup=${6:-}
    for ((i = 1; i <= runs; i++)); do
        clean_tmp
        build_schedule "$schedule"
        run_main
        silent sudo mv /tmp/history.txt "$output_folder/$i.txt"
        silent sh "$oracle" "$i" "$output_folder"
        [[ -n $cleanup ]] && silent sh "$cleanup"
    done
fi
