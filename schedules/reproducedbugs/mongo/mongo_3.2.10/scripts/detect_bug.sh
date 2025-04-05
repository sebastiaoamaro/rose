#!/bin/bash

# File to check
FILE=$1
SEARCH_STRING="PRIMARY"

# Check if file exists
if [[ ! -f "$FILE" ]]; then
    echo "File does not exist."
    exit 1
fi

# Get lines matching the search string
MATCHING_LINES=$(grep "$SEARCH_STRING" "$FILE")

# Check if the search string is found
if [[ -z "$MATCHING_LINES" ]]; then
    exit 1
fi

# Count the number of matching lines
LINE_COUNT=$(echo "$MATCHING_LINES" | wc -l)

# Check if more than 3 matching lines
if [[ $LINE_COUNT -gt 4 ]]; then
    echo "There are more than 4 lines matching '$SEARCH_STRING'!"
    # Add your action here
fi
