#!/bin/bash

# Check if input file and script are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <keywords_file> <binary> <output_file>"
    exit 1
fi

keywords_file="$1"
binary="$2"
functions_file="function_symbols.txt"
output_file="$3"

if [ ! -f "$functions_file" ]; then
    echo "Deleting existing functions file"
    rm "$functions_file"
fi

if [ ! -f "$keywords_file" ]; then
    echo "Error: Keywords file '$keywords_file' not found"
    exit 1
fi

while IFS= read -r keyword || [ -n "$keyword" ]; do
    echo "Processing keyword: '$keyword'"
    ./get_symbols.sh $binary "$keyword" "function_symbols.txt"
    if [ $? -ne 0 ]; then
        echo "Warning: Script failed for keyword '$keyword'"
    fi
done < "$keywords_file"

./get_offsets.sh $binary $functions_file $output_file

echo "All keywords processed."
