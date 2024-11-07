import sys

def filter_lines_by_time(file_name, time_in_seconds):

    probes_to_remove = []

    # Open the file and read lines
    with open(file_name, 'r') as file:
        lines = file.readlines()

    # Iterate through each line
    for line in lines[:-1]:
        # Strip any extra whitespace and split by comma

        if line == "probes_to_remove:":
            break

        parts = line.strip().split(',')
        
        if len(parts) != 2:
            print(f"Invalid format in line: {line.strip()}")
            continue

        try:
            # Convert the pos and counter values
            pos = int(parts[0])     # First value is pos
            counter = int(parts[1]) # Second value is counter

            # Calculate counter/time ratio
            ratio = counter / time_in_seconds

            # Print the line if ratio is greater than 1
            print("Ratio is "+str(ratio))
            if ratio > 2:
                probes_to_remove.append(pos)
                

        except ValueError:
            print(f"Error: Non-integer value in line: {line.strip()}")

    return probes_to_remove


def delete_lines_from_file(file_name, lines_to_delete):
    try:
        # Open the file and read all lines
        with open(file_name, 'r') as file:
            lines = file.readlines()

        # Create a new list that excludes the lines to be deleted
        updated_lines = [line for i, line in enumerate(lines, start=0) if i not in lines_to_delete]

        # Write the updated lines back to the file (overwrite the file)
        with open(file_name, 'w') as file:
            file.writelines(updated_lines)

        print(f"Successfully deleted lines: {lines_to_delete}")

    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":

    file_name = sys.argv[1]

    time = int(sys.argv[2])

    functions_file = sys.argv[3]

    print("Started removing probes: file is "+str(file_name)+", time is: " +str(time))

    lines_to_delete = filter_lines_by_time(file_name, time)
    delete_lines_from_file(functions_file,lines_to_delete)



