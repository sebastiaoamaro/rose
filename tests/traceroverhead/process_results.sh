#!/bin/bash
# Define the file with numbers
file=$1
results=$2
runs=$3

echo $1
echo $2
# Initialize variables
sum=0
count=0
block_number=0

strings=("vanilla" "intercept" "intercept_and_count" "count_syscalls" "save_info" "save_io")

calculate_median() {
    sorted_numbers=($(printf "%s\n" "${numbers[@]}" | sort -n))  # Sort the numbers
    num_count=${#sorted_numbers[@]}  # Get the count of numbers

    if (( num_count % 2 == 1 )); then
        # Odd number of elements, take the middle one
        median=${sorted_numbers[$((num_count / 2))]}
    else
        # Even number of elements, take the average of the two middle ones
        mid=$((num_count / 2))
        median=$(awk -v a="${sorted_numbers[$mid]}" -v b="${sorted_numbers[$((mid - 1))]}" 'BEGIN {print (a + b) / 2}')
    fi

    echo "$median"
}

calculate_stddev() {
    # Calculate the mean
    mean=$(awk -v sum="$sum" -v count="$count" 'BEGIN {print sum / count}')
    
    # Calculate the squared differences and sum them
    sum_sq_diff=0
    for num in "${numbers[@]}"; do
        sq_diff=$(awk -v num="$num" -v mean="$mean" 'BEGIN {print (num - mean) * (num - mean)}')
        sum_sq_diff=$(awk -v sum_sq_diff="$sum_sq_diff" -v sq_diff="$sq_diff" 'BEGIN {print sum_sq_diff + sq_diff}')
    done
    
    # Calculate the variance and standard deviation
    variance=$(awk -v sum_sq_diff="$sum_sq_diff" -v count="$count" 'BEGIN {print sum_sq_diff / count}')
    stddev=$(awk -v variance="$variance" 'BEGIN {print sqrt(variance)}')
    
    echo "$stddev"
}

# Open the file and loop through it line by line
while read -r line; do
    # Add the current number to the list of numbers and update the sum
    numbers+=("$line")
    sum=$(awk -v sum="$sum" -v line="$line" 'BEGIN {print sum + line}')
    count=$((count + 1))

    if (( count == runs )); then
        # Get the current block name from the list
        block_name=${strings[$block_number]}
        
        # Calculate the average
        average=$(awk -v sum="$sum" -v count="$count" 'BEGIN {print sum / count}')
        
        # Calculate the median
        median=$(calculate_median)

        # Calculate the standard deviation
        stddev=$(calculate_stddev)
        
        # Print the result with the block name
        echo "Block: $block_name" >> $results
        echo "Average: $average" >> $results
        echo "Median: $median" >> $results
        echo "Standard Deviation: $stddev" >> $results
        
        # Reset variables for the next block
        sum=0
        count=0
        block_number=$((block_number + 1))
        numbers=()  # Reset the numbers array
    fi
done < "$file"