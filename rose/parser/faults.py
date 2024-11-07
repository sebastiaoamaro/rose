from conditions import build_file_syscall, build_syscall, build_user_function, get_cond_type_nr,build_fault_conditions,file_syscall,build_time

class Fault:
    name = ""
    type = ""
    fault_category = 0
    fault_specifics = None
    target = ""
    target_nr = 0
    traced = ""
    traced_nr = 0
    repeatable = 0
    duration = 0
    occurrences = 0
    begin_conditions = []
    end_conditions = []
    trigger_statement_begin = ""
    trigger_statement_end = ""
    exit = 0

#Type of faults
class file_system_operation:
    syscal_name = ""
    directory_name = ""
    file_name = ""
    success = 0
    return_value = 0

class syscall:
    syscall_name = ""
    success = 0
    return_value = 0

class network_partition:
    network_partitions = {}
    node_count = 0
    nodes_in_partitions = []

class block_ips:
    nodes_in = []
    nodes_out = []

class packet_dropping:
    packet_loss = 0.0

class process_fault:
    type = 0

def parse_faults(faults,nodes):

    faults_dict = {}
    for key,value in faults.items():
        faults_dict[key] = createFault(key,value,nodes)
    return faults_dict


def createFault(name,faultconfig,nodes_dict):

    fault = Fault()

    fault.name = name

    fault.type = faultconfig['type']

    if fault.type == 'network_partition':

        network_partition_fault = network_partition()

        node_count = 0
        nodes_in_partitions = []
        for name,partition in faultconfig['network_partitions'].items():
            nodes = []
            for node in partition.split():
                node_count+=1
                nodes_in_partitions.append(node)
                nodes.append(node)

            network_partition_fault.network_partitions[name] = nodes
            network_partition_fault.node_count = node_count
        network_partition_fault.nodes_in_partitions = nodes_in_partitions
        fault.fault_specifics = network_partition_fault
        fault.fault_category = 0

    if fault.type == 'block_ips':
        fault.fault_category = 0
        block_ips_fault = block_ips()

        nodes_in = []
        nodes_out = []
        if "ips_in" in faultconfig:
            for node in faultconfig['ips_in'].split():
                nodes_in.append(node)
        if "ips_out" in faultconfig:
            for node in faultconfig['ips_out'].split():
                nodes_out.append(node)


        block_ips_fault.nodes_in = nodes_in
        block_ips_fault.nodes_out = nodes_out


        fault.fault_specifics = block_ips_fault
    if fault.type == "drop_packets":
        fault.fault_category = 0

    if fault.type == "file_system_operation":
            fault.fault_category = 3
            file_system_operation_fault = file_system_operation()

            file_system_operation_fault.syscall_name = faultconfig['details']['name']

            if 'file_name' in faultconfig['details']:
                file_system_operation_fault.file_name = faultconfig['details']['file_name']

            if 'directory_name' in faultconfig['details']:
                file_system_operation_fault.directory_name = faultconfig['details']['directory_name']

            # success = faultconfig['details']['success']
            
            # if success == "True":
            #     file_system_operation_fault.success = 1
            # else:
            #     file_system_operation_fault.success = 0
            file_system_operation_fault.return_value = faultconfig['details']['return_value']

            fault.fault_specifics = file_system_operation_fault

    if fault.type == "syscall":
        fault.fault_category = 2
        syscall_fault = syscall()
        syscall_fault.syscall_name = faultconfig['details']['name']
        syscall_fault.return_value = faultconfig['details']['return_value']

        fault.fault_specifics = syscall_fault

    if fault.type == "process_kill" or fault.type == "process_pause" or fault.type == "process_restart":
        fault.fault_category = 1

    if 'traced' in faultconfig:
        fault.traced = faultconfig['traced']
        for name,node in nodes_dict.items():
            if name == fault.traced:
                fault.traced_nr = node.node_nr

    if 'target' in faultconfig:
        fault.target = faultconfig['target']
        for name,node in nodes_dict.items():
            if name == fault.target:
                fault.target_nr = node.node_nr

        if fault.target == "primary":
            fault.target_nr = -1
        if fault.target == "majority":
            fault.target_nr = -2

    if 'repeatable' in faultconfig:

        repeatable = faultconfig['repeatable']

        if(repeatable == "True"):
            fault.repeatable = 1

    if 'duration' in faultconfig:
        fault.duration = faultconfig['duration']

    if 'occurrences' in faultconfig:
        fault.occurrences = faultconfig['occurrences']

    if 'exit' in faultconfig:
        fault.exit = 1 if faultconfig['exit'] else 0

    #fault.trigger_statement_begin = faultconfig['begin_conditions']['trigger_statement']

    begin_conditions = faultconfig['begin_conditions']
    
    fault.begin_conditions = []

    conditions_count = 0
    for name,condition in begin_conditions.items():

        type_cond = condition['type']
        if type_cond == 'trigger_statement':
            continue

        if type_cond == 'user_function':
            condition = build_user_function(condition)
            cond_nr = get_cond_type_nr(1,condition)
            # condition.cond_nr = cond_nr
            fault.begin_conditions.append(condition)

        if type_cond == 'file_syscall':
            condition = build_file_syscall(condition)
            cond_nr = get_cond_type_nr(2,condition)
            condition.cond_nr = cond_nr
            fault.begin_conditions.append(condition)
        
        if type_cond == "syscall":
            condition = build_syscall(condition)
            cond_nr = get_cond_type_nr(3,condition)
            condition.cond_nr = cond_nr
            fault.begin_conditions.append(condition)
        
        if type_cond == "time":
            condition = build_time(condition)
            fault.begin_conditions.append(condition)

    if 'end_conditions' in faultconfig:
        fault.trigger_statement_end = faultconfig['end_conditions']['trigger_statement']

        end_conditions = faultconfig['end_conditions']

        conditions_count = 0
        for name,value in end_conditions.items():
            #todo
            continue

    return fault

def build_faults_cfile(file,nodes,faults):
    
    build_faults_begin = """\nfault* build_faults_extra(){\n"""
    file.write(build_faults_begin)

    build_faults_malloc = """    fault* faults = ( fault*)malloc(FAULT_COUNT * sizeof(fault));\n"""
    file.write(build_faults_malloc)

    fault_count = 0
    for name,fault in faults.items():
        if fault.type != "network_partition":
            create_fault_detail_var = """    fault_details fault_details#fault_nr;\n"""
            create_fault_detail_var = create_fault_detail_var.replace("#fault_nr",str(fault_count))
            file.write(create_fault_detail_var)

            fault_type_nr = get_fault_type_nr(fault.type,fault.fault_specifics)

            fault_details = None

            fault_details = build_fault_details(fault.type,fault_type_nr,fault_count,fault.fault_specifics,nodes,"")

            file.write(fault_details)
            build_fault = """    create_fault(&faults[#faultnr],"#name",#target,#traced,#faulttype,#fault_category,fault_details#fault_nr,#repeat,#occurrences,#duration,#condition_count,#exit);\n\n"""

            build_fault = build_fault.replace("#faultnr",str(fault_count))
            build_fault = build_fault.replace("#name",fault.name)
            build_fault = build_fault.replace("#target",str(fault.target_nr))
            build_fault = build_fault.replace("#traced",str(fault.traced_nr))

            build_fault = build_fault.replace("#faulttype",str(fault_type_nr))

            build_fault = build_fault.replace("#fault_category",str(fault.fault_category))
            build_fault = build_fault.replace("#fault_nr",str(fault_count))
            build_fault = build_fault.replace("#repeat",str(fault.repeatable))
            build_fault = build_fault.replace("#occurrences",str(fault.occurrences))
            build_fault = build_fault.replace("#duration",str(fault.duration))
            build_fault = build_fault.replace("#condition_count",str(len(fault.begin_conditions)))
            build_fault = build_fault.replace("#exit",str(fault.exit))
            # build_fault = build_fault.replace("#faultnr",str(fault_count))
            # build_fault = build_fault.replace("#faultnr",str(fault_count))
            file.write(build_fault)

            build_fault_conditions(file,fault_count,fault.begin_conditions)

            fault_count+=1
        else:
            comment_network_partition = """    //network partition begins\n"""
            file.write(comment_network_partition)
            for node in fault.fault_specifics.nodes_in_partitions:
                create_fault_detail_var = """    fault_details fault_details#fault_nr;\n"""
                create_fault_detail_var = create_fault_detail_var.replace("#fault_nr",str(fault_count))
                file.write(create_fault_detail_var)

                fault_type_nr = str(5)
    
                fault_details = build_fault_details(fault.type,fault_type_nr,fault_count,fault.fault_specifics,nodes,node)

                file.write(fault_details)
                target_nr = nodes[node].node_nr

                build_fault = """    create_fault(&faults[#faultnr],"#name",#target,#traced,#faulttype,#fault_category,fault_details#fault_nr,#repeat,#occurrences,#duration,#condition_count,#exit);\n\n"""

                build_fault = build_fault.replace("#faultnr",str(fault_count))
                build_fault = build_fault.replace("#name","block_ips")
                build_fault = build_fault.replace("#target",str(target_nr))
                build_fault = build_fault.replace("#traced",str(fault.traced_nr))

                build_fault = build_fault.replace("#faulttype",str(fault_type_nr))
                build_fault = build_fault.replace("#fault_category",str(fault.fault_category))

                build_fault = build_fault.replace("#fault_nr",str(fault_count))
                build_fault = build_fault.replace("#repeat",str(fault.repeatable))
                build_fault = build_fault.replace("#occurrences",str(fault.occurrences))
                build_fault = build_fault.replace("#duration",str(fault.duration))
                build_fault = build_fault.replace("#condition_count",str(len(fault.begin_conditions)))
                build_fault = build_fault.replace("#exit",str(fault.exit))

                file.write(build_fault)
                build_fault_conditions(file,fault_count,fault.begin_conditions)
                
                fault_count+=1
            comment_network_partition = """    //network partition ends\n"""
            file.write(comment_network_partition)
    build_faults_end= """
    return faults;
}"""
    file.write(build_faults_end)

def build_fault_details(fault_type,fault_type_nr,fault_nr,fault_specifics,nodes,node_name):
    match fault_type:
        case "block_ips":
            block_ips_definition = """    block_ips block_ips#nr;\n"""
            block_ips_definition = block_ips_definition.replace("#nr",str(fault_nr))
            ip_count_in = 0
            ip_count_out = 0

            for name in fault_specifics.nodes_in:
                add_ip_block_line = """    add_ip_to_block_extra(&block_ips#nr,"#ipname",#ipnr,#direction);\n"""

                ip = nodes[name].ip
                add_ip_block_line = add_ip_block_line.replace("#nr",str(fault_nr))
                add_ip_block_line = add_ip_block_line.replace("#ipname",str(ip))
                add_ip_block_line = add_ip_block_line.replace("#ipnr",str(ip_count_in))
                add_ip_block_line = add_ip_block_line.replace("#direction",str(1))
                block_ips_definition = block_ips_definition + add_ip_block_line
                ip_count_in+=1

            for name in fault_specifics.nodes_out:
                add_ip_block_line = """    add_ip_to_block_extra(&block_ips#nr,"#ipname",#ipnr,#direction);\n"""

                ip = nodes[name].ip
                add_ip_block_line = add_ip_block_line.replace("#nr",str(fault_nr))
                add_ip_block_line = add_ip_block_line.replace("#ipname",str(ip))
                add_ip_block_line = add_ip_block_line.replace("#ipnr",str(ip_count_out))
                add_ip_block_line = add_ip_block_line.replace("#direction",str(2))
                block_ips_definition = block_ips_definition + add_ip_block_line
                ip_count_out+=1


            assign_line = """    fault_details#nr.block_ips = block_ips#nr;\n"""
            assign_line += """    fault_details#nr.block_ips.count_in = #ip_count_in;\n"""
            assign_line += """    fault_details#nr.block_ips.count_out = #ip_count_out;\n"""

            assign_line = assign_line.replace("#ip_count_in",str(ip_count_in))
            assign_line = assign_line.replace("#ip_count_out",str(ip_count_out))

            assign_line = assign_line.replace("#nr",str(fault_nr))
            
            block_ips_definition+= assign_line
            return block_ips_definition
        
        case "drop_packets":
            return ""
        case "network_partition":
            ips_to_block = []
            for name,partition in fault_specifics.network_partitions.items():
                if node_name in partition:
                    for node in nodes:
                        if node not in partition:
                            ips_to_block.append(node)

            block_ips_definition = """    block_ips block_ips#nr;\n"""
            block_ips_definition = block_ips_definition.replace("#nr",str(fault_nr))
            ip_count = 0
            for name in ips_to_block:
                add_ip_block_line = """    add_ip_to_block_extra(&block_ips#nr,"#ipname",#ipnr,#direction);\n"""

                ip = nodes[name].ip
                add_ip_block_line = add_ip_block_line.replace("#nr",str(fault_nr))
                add_ip_block_line = add_ip_block_line.replace("#ipname",str(ip))
                add_ip_block_line = add_ip_block_line.replace("#ipnr",str(ip_count))
                add_ip_block_line = add_ip_block_line.replace("#direction",str(1))
                block_ips_definition = block_ips_definition + add_ip_block_line

                add_ip_block_line = """    add_ip_to_block_extra(&block_ips#nr,"#ipname",#ipnr,#direction);\n"""
                add_ip_block_line = add_ip_block_line.replace("#nr",str(fault_nr))
                add_ip_block_line = add_ip_block_line.replace("#ipname",str(ip))
                add_ip_block_line = add_ip_block_line.replace("#ipnr",str(ip_count))
                add_ip_block_line = add_ip_block_line.replace("#direction",str(2))
                block_ips_definition = block_ips_definition + add_ip_block_line

                ip_count+=1

            assign_line = """    fault_details#nr.block_ips = block_ips#nr;\n"""
            assign_line += """    fault_details#nr.block_ips.count_in = #ip_count;\n"""
            assign_line += """    fault_details#nr.block_ips.count_out = #ip_count;\n"""
            assign_line = assign_line.replace("#ip_count",str(ip_count))
            assign_line = assign_line.replace("#nr",str(fault_nr))
            block_ips_definition+= assign_line
            return block_ips_definition
        case "process_kill":
            process_kill_definition = """    process_fault process_kill#nr;\n"""
            process_kill_definition = process_kill_definition.replace("#nr",str(fault_nr))

            process_kill_definition += """    process_kill#nr.type = #fault_type_nr;\n"""
            process_kill_definition = process_kill_definition.replace("#fault_type_nr",str(fault_type_nr))
            process_kill_definition += """    fault_details#nr.process_fault = process_kill#nr;\n"""
            process_kill_definition = process_kill_definition.replace("#nr",str(fault_nr))
            return process_kill_definition
        case "process_pause":
            process_pause_definition = """    process_fault process_pause#nr;\n"""
            process_pause_definition = process_pause_definition.replace("#nr",str(fault_nr))

            process_pause_definition += """    process_pause#nr.type = #fault_type_nr;\n"""
            process_pause_definition = process_pause_definition.replace("#fault_type_nr",str(fault_type_nr))
            process_pause_definition += """    fault_details#nr.process_fault = process_pause#nr;\n"""
            process_pause_definition = process_pause_definition.replace("#nr",str(fault_nr))
            return process_pause_definition
        case "process_restart":
            process_restart_definition = """   process_fault process_restart#nr;\n"""
            process_restart_definition = process_restart_definition.replace("#nr",str(fault_nr))

            process_restart_definition += """  process_restart#nr.type = #fault_type_nr;\n"""
            process_restart_definition = process_restart_definition.replace("#fault_type_nr",str(fault_type_nr))
            process_restart_definition += """  fault_details#nr.process_fault = process_restart#nr;\n"""
            process_restart_definition = process_restart_definition.replace("#nr",str(fault_nr))
            return process_restart_definition
        
        case "syscall":
            syscall_definition = """    syscall_operation syscall#nr;\n"""
            syscall_definition += """    syscall#nr.syscall = #fault_type_nr;\n"""
            syscall_definition = syscall_definition.replace("#fault_type_nr",str(fault_type_nr))
            syscall_definition += """    syscall#nr.success = #success;\n"""
            syscall_definition = syscall_definition.replace("#success",str(fault_specifics.success))
            syscall_definition += """    syscall#nr.return_value = #return_value;\n"""
            syscall_definition = syscall_definition.replace("#return_value",str(fault_specifics.return_value))
            syscall_definition += """    fault_details#nr.syscall = syscall#nr;\n"""
            syscall_definition = syscall_definition.replace("#nr",str(fault_nr))
            return syscall_definition
        case "file_system_operation":
            file_sys_op = """    file_system_operation file_syscall#nr;\n"""
            file_sys_op += """    file_syscall#nr.syscall = #fault_type_nr;\n"""
            file_sys_op = file_sys_op.replace("#fault_type_nr",str(fault_type_nr))
            file_sys_op += """    file_syscall#nr.syscall_condition = #condition_nr;\n"""
            #Need to know which cond this is, because one thing is fault and the other is cond
            temporary_condition = file_syscall()
            temporary_condition.syscall_name = fault_specifics.syscall_name
            file_sys_op = file_sys_op.replace("#condition_nr",str(get_cond_type_nr(2,temporary_condition)))

            if len(fault_specifics.directory_name) > 0:
                file_sys_op += """    strcpy(file_syscall#nr.directory_name,"#directory_name");\n"""
                file_sys_op = file_sys_op.replace("#directory_name",fault_specifics.directory_name)
                #file_sys_op = file_sys_op.replace("#string_size",str(len(fault_specifics.directory_name)))
            else:
                file_sys_op += """    strcpy(file_syscall#nr.directory_name,"#directory_name");\n"""
                file_sys_op = file_sys_op.replace("#directory_name","")
                #file_sys_op = file_sys_op.replace("#string_size","1")
            if len(fault_specifics.file_name) > 0:
                file_sys_op += """    strcpy(file_syscall#nr.file_name,"#file_name");\n"""
                file_sys_op = file_sys_op.replace("#file_name",fault_specifics.file_name)
                #file_sys_op = file_sys_op.replace("#string_size",str(len(fault_specifics.file_name)))
            else:
                file_sys_op += """    strcpy(file_syscall#nr.file_name,"#file_name");\n"""
                file_sys_op = file_sys_op.replace("#file_name","") 
                #file_sys_op = file_sys_op.replace("#string_size","1")


            file_sys_op += """    file_syscall#nr.success = #success;\n"""
            file_sys_op = file_sys_op.replace("#success",str(fault_specifics.success))
            file_sys_op += """    file_syscall#nr.return_value = #return_value;\n"""
            file_sys_op = file_sys_op.replace("#return_value",str(fault_specifics.return_value))
            file_sys_op += """    fault_details#nr.file_system_op = file_syscall#nr;\n"""
            file_sys_op = file_sys_op.replace("#nr",str(fault_nr))

            return file_sys_op
        

def get_fault_type_nr(type,fault_specifics):

    match type:
        case "network_isolation":
            return 4
        case "block_ips":
            return 5
        case "drop_packets":
            return 6
        case "process_kill":
            return 11
        case "process_pause":
            return 14
        case "process_restart":
            return 22
        case "syscall":
            match fault_specifics.syscall_name:
                #Needs success = 0
                case "write":
                    return 2
                case "read":
                    return 3
                case "open":
                    return 15
                case "mkdir":
                    return 23
                case "newfstatat":
                    return 17
                case "openat":
                    return 18
                case "fdatasync":
                    return "FDATASYNC_FAULT"
        case "file_system_operation":
            match fault_specifics.syscall_name:
                case "write":
                    return 8
                case "read":
                    return 9
                case "mkdir":
                    return 23
                case "newfstatat":
                    return 24
                case "openat":
                    return 25
                case "open":
                    return 20
                case "fdatasync":
                    return "FDATASYNCFILE_FAULT"
    return 0

