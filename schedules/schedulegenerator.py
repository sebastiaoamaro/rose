import sys
import subprocess
import re
import yaml
from collections import OrderedDict

def hex_subtract(hex1, hex2):
    """Subtract two hexadecimal numbers and return the result in decimal."""
    # Convert hexadecimal strings to integers
    int1 = int(hex1, 16)
    int2 = int(hex2, 16)

    # Perform the subtraction
    result = int2 - int1

    # Return the result in decimal
    return result

def extract_address(line):
    """ Extract the address from a disassembly line. """
    # Define regex pattern to capture the address up to the colon
    pattern = re.compile(r'^\s*([0-9a-fA-F]+):')

    match = pattern.match(line)
    if match:
        # Return the address as a string
        return match.group(1)
    else:
        # Return None or an empty string if no match
        return None

def run_objdump(binary_path):
    """ Run objdump to disassemble the binary and return the output. """
    result = subprocess.run(
        ['objdump', '-d', binary_path],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout

def extract_instructions(disassembly, function_name):
    start_pattern = re.compile(rf'^\s*[0-9a-fA-F]+ <{re.escape(function_name)}>:')

    # Split disassembly into lines
    lines = disassembly.splitlines()

    # Find the start of the function
    function_started = False
    instructions = []

    for line in lines:
        if start_pattern.match(line):
            function_started = True
            continue

        if function_started:
            # Stop at an empty line
            if not line.strip():
                break

            # Check for indented lines that are likely instructions
            #if re.match(r'^\s+[0-9a-fA-F]+:', line):  # Look for instruction lines with addresses
            instructions.append(line)

    return instructions


def calculate_offsets(binary_path, function_name):
    # Open the binary file
    disassembly = run_objdump(binary_path)
    instructions = extract_instructions(disassembly, function_name)

    addresses = []
    for instruction in instructions:
        addr = extract_address(instruction)
        addresses.append(addr)

    offsets = []
    base = addresses[0]
    for addr in addresses[1:]:
        offset = hex_subtract(base,addr)
        offsets.append(offset)

    return offsets

def ordered_load(stream, loader=yaml.Loader):
    """ Load YAML while preserving order. """
    return yaml.load(stream, Loader=loader)

def create_new_schedule(file_path,new_file, new_value,function_name):
    """ Update all fields with key 'offset' in a YAML file with a new integer value, preserving order. """

    # Load the YAML file while preserving order
    with open(file_path, 'r') as file:
        data = ordered_load(file, yaml.SafeLoader)

    # Function to update 'offset' fields

    def update_offsets(d):
        if isinstance(d, dict):
            for key in d:
                if key == 'begin_conditions':
                    conditions = d['begin_conditions']
                    for cond in conditions:
                        cond = conditions[cond]
                        if cond['type'] == 'user_function':
                            if cond['symbol'] == function_name:
                                cond['offset'] = new_value
                else:
                    update_offsets(d[key])
        elif isinstance(d, list):
            for item in d:
                update_offsets(item)

    # Update the data
    update_offsets(data)

    # Save the updated YAML file, preserving order
    with open(new_file, 'w') as file:
        yaml.dump(data, file, Dumper=yaml.SafeDumper, sort_keys=False)

def main():
    base_schedule = sys.argv[1]

    mode = sys.argv[2]

    if mode == "function":

        if len(sys.argv) != 6:
            print("You must give the binary, function_name and the outputfolder")
            return
        binary = sys.argv[3]

        function_name = sys.argv[4]

        output_folder = sys.argv[5]

        create_schedules_based_on_offset(output_folder,base_schedule,binary,function_name)

    if mode == "call_count":
        if len(sys.argv) != 7:
            print("You must give the fault nr, cond nr and the outputfolder")
            return
        fault_name = sys.argv[3]
        cond_name = sys.argv[4]
        call_count_max = int(sys.argv[5])

        output_folder = sys.argv[6]

        create_schedules_based_changing_call_count(output_folder,base_schedule,fault_name,cond_name,call_count_max)

def create_schedules_based_on_offset(output_folder,base_schedule,binary,function_name):
    offsets = calculate_offsets(binary,function_name)

    for offset in offsets:
        create_new_schedule(base_schedule,output_folder+"test"+str(offset)+".yaml",offset,function_name)

def create_schedules_based_changing_call_count(output_folder,base_schedule,fault_name,cond_name,call_count_max):
    with open(base_schedule, 'r') as file:
        data = ordered_load(file, yaml.SafeLoader)

        for i in range(1,call_count_max+1):
            print(data["faults"])
            for j in range(0,len(data["faults"][fault_name]["begin_conditions"])):
                cond = data["faults"][fault_name]["begin_conditions"][j]
                if cond_name in cond:
                    data["faults"][fault_name]["begin_conditions"][j][cond_name]["call_count"] = i
                    new_file = output_folder+"test"+str(i)+".yaml"
                    with open(new_file, 'w') as file:
                        yaml.dump(data, file, Dumper=yaml.SafeDumper, sort_keys=False)

if __name__ == "__main__":
    main()
