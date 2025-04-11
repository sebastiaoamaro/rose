#!/bin/bash

# This script is used to convert a file of function names to their offset
gcc -o find_function find_function_offset.c -lelf
if [ $# -ne 3 ]; then
    echo "Usage: $0 <binary_file> <function_file> <output_file>"
    exit 1
fi

# Check if the binary file exists
if [ ! -f $1 ]; then
    echo "Error: $1 does not exist"
    exit 1
fi
# Cycle function names and find its offset
while IFS= read -r function_name; do
    echo "Finding offset of: $function_name"
    offset=$(sudo ./find_function $1 $function_name)
    echo $offset >> $3
done < $2
