import sys
import subprocess
import re
import yaml
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
