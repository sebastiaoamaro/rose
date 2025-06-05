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
    """Extract the address from a disassembly line, ignoring padding (all 00 bytes)."""
    # Regex pattern to capture the address at the start of the line
    address_pattern = re.compile(r'^\s*([0-9a-fA-F]+):')
    address_match = address_pattern.match(line)

    if not address_match:
        return None  # No address found

    # Extract the address
    address = address_match.group(1)

    # Check if the rest of the line contains only "00" bytes (padding)
    # Split the line after the address to isolate machine code bytes
    machine_code_part = line[address_match.end():].strip()
    # Split into individual bytes (e.g., ["00", "01", ...])
    bytes_list = machine_code_part.split()

    # Return None if all bytes are "00"
    if all(byte == "00" for byte in bytes_list):
        return None

    return address

def check_plt_address(line):
    """Extract the address from a disassembly line, ignoring padding (all 00 bytes) and lines without @plt or call."""
    # Regex pattern to capture the address at the start of the line
    address_pattern = re.compile(r'^\s*([0-9a-fA-F]+):')
    address_match = address_pattern.match(line)

    if not address_match:
        return None  # No address found

    # Extract the address
    address = address_match.group(1)

    # Check if the rest of the line contains only "00" bytes (padding)
    machine_code_part = line[address_match.end():].strip()
    bytes_list = machine_code_part.split()
    if all(byte == "00" for byte in bytes_list):
        return None

    # Check if line contains "@plt" or "call" (case-insensitive)
    if '@plt' not in line:
        return None

    return address

def check_call_address(line):
    """Extract the address from a disassembly line, ignoring padding (all 00 bytes) and lines without @plt or call."""
    # Regex pattern to capture the address at the start of the line
    address_pattern = re.compile(r'^\s*([0-9a-fA-F]+):')
    address_match = address_pattern.match(line)

    if not address_match:
        return None  # No address found

    # Extract the address
    address = address_match.group(1)

    # Check if the rest of the line contains only "00" bytes (padding)
    machine_code_part = line[address_match.end():].strip()
    bytes_list = machine_code_part.split()
    if all(byte == "00" for byte in bytes_list):
        return None

    # Check if line contains "@plt" or "call" (case-insensitive)
    if 'call' not in line.lower():
        return None

    return address

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
        if not addr is None:
            addresses.append(addr)

    offsets = []
    base = addresses[0]
    for addr in addresses[1:]:
        offset = hex_subtract(base,addr)
        offsets.append(offset)

    return offsets


def calculate_call_offsets(binary_path, function_name):
    # Open the binary file
    disassembly = run_objdump(binary_path)
    instructions = extract_instructions(disassembly, function_name)

    addresses = []
    addresses.append(extract_address(instructions[0]))
    for instruction in instructions[1:]:
        addr = check_call_address(instruction)
        if not addr is None:
            addresses.append(addr)

    offsets = []
    base = addresses[0]
    for addr in addresses[1:]:
        offset = hex_subtract(base,addr)
        offsets.append(offset)

    return offsets

def calculate_plt_offsets(binary_path, function_name):
    # Open the binary file
    disassembly = run_objdump(binary_path)
    instructions = extract_instructions(disassembly, function_name)

    addresses = []
    addresses.append(extract_address(instructions[0]))
    for instruction in instructions[1:]:
        addr = check_plt_address(instruction)
        if not addr is None:
            addresses.append(addr)

    offsets = []
    base = addresses[0]
    for addr in addresses[1:]:
        offset = hex_subtract(base,addr)
        offsets.append(offset)

    return offsets
