def calculate_fault_count(faults):
    fault_count = 0
    for name,fault in faults.items():
        if fault.type == "network_partition":
            for name,partition in fault.fault_specifics.network_partitions.items():
                fault_count += len(partition)
        else:
            fault_count+=1
    return fault_count