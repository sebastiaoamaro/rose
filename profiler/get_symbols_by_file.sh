#!/bin/bash
# Check if input file and script are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <relevant_files> <binary> <output_file>"
    exit 1
fi
cd /vagrant/profiler/

relevant_files="$1"
binary="$2"
output_file="$3"
functions_file="functions_symbols.txt"
functions_binary="functions_binary.txt"

if [ -f "$functions_file" ]; then
    echo "Deleting existing functions file"
    rm "$functions_file"
fi

if [ -f "$functions_binary" ]; then
    echo "Deleting existing functions binary"
    rm "$functions_binary"
fi

if [ ! -f "$relevant_files" ]; then
    echo "Error: Relevant files file '$relevant_files' not found"
    exit 1
fi

readelf -Ws $binary | grep -v "UND" | grep -v ".cold" | awk '{print $2, $8}' > $functions_binary

while IFS= read -r filename; do
    while IFS= read -r line; do
        addr=$(echo "$line" | cut -d' ' -f1)
        symbol=$(echo "$line" | cut -d' ' -f2)
        function_location=$(addr2line -e $binary "$addr")
        if echo "$function_location" | grep -q $filename; then
            echo $symbol >> $functions_file
        fi
    done < $functions_binary
done < "$relevant_files"

./get_offsets.sh $binary $functions_file $output_file

grep -v "ERROR" $output_file > "temp_functions.txt"

python3 remove_duplicates.py "temp_functions.txt" $output_file

rm "temp_functions.txt"

rm "$functions_file"

rm "$functions_binary"
