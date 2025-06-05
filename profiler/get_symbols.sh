#!/bin/bash

# Check if the correct number of arguments are provided
if [ $# -ne 3 ]; then
    echo "Usage: $0 <binary_file> <keyword> <output_file>"
    exit 1
fi

# Arguments
BINARY_FILE=$1
KEYWORD=$2
OUTPUT_FILE=$3

# Check if the binary file exists
if [ ! -f "$BINARY_FILE" ]; then
    echo "Error: Binary file $BINARY_FILE does not exist."
    exit 1
fi

# Extract function symbols, exclude weak, undefined, and cold symbols,
# filter by the specified keyword, and save to the output file
echo "Extracting and filtering function symbols from $BINARY_FILE..."
readelf -sW "$BINARY_FILE" | awk -v keyword="$KEYWORD" '$4 == "FUNC" && $5 != "WEAK" && $5 != "UNDEF" && $5 != "cold" && tolower($8) ~ tolower(keyword) {print $8}' >> "$OUTPUT_FILE"

# Check if the operation was successful
if [ $? -eq 0 ]; then
    echo "Filtered function symbols saved to $OUTPUT_FILE."
else
    echo "Failed to extract and filter function symbols."
fi
