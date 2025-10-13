def calculate_fault_count(faults):
    fault_count = 0
    for name, fault in faults.items():
        fault_count += 1
    return fault_count
