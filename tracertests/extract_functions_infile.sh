#!/bin/bash
readelf -Ws $1 | grep -v "UND" | grep -v ".cold" | awk '{print $2, $8}' > functions_binary.txt

# Loop through each line in the file
while IFS= read -r line; do
    # Extract the address (first field) and function name (second field)
    addr=$(echo "$line" | cut -d' ' -f1)
    symbol=$(echo "$line" | cut -d' ' -f2)

    # Get the source location of the address using addr2line
    function_location=$(addr2line -e $1 "$addr")

    # Check if the file in function_location contains $2
    if echo "$function_location" | grep -q $2; then
        echo $symbol >> $3
    fi

done < functions_binary.txt 