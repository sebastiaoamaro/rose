import yaml
import sys

class Node:
    name = ""
    pid = 0
    veth = ""
    ip = ""
    container_pid: 0
    script = ""
    node_nr = 0

class Fault:
    name = ""
    type = ""
    fault_category = 0
    fault_specifics = None
    target = ""
    target_nr = 0
    repeatable = 0
    duration = 0
    occurrences = 0
    begin_conditions = []
    end_conditions = []
    trigger_statement_begin = ""
    trigger_statement_end = ""


#Fault stuff
class file_system_operation:
    name = ""
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
    block_ips = []

class packet_dropping:
    packet_loss = 0.0

class process_fault:
    type = 0

#Condition stuff
class user_function_condition:
    binary_location = ""
    symbol = ""
    arguments = []
    call_count = 0


class file_syscall:
    syscall_name = ""
    cond_nr = 0
    directory_name = ""
    file_name = ""
    call_count = 0
    cond_nr = 0

class syscall_condition:
    syscall_name = ""
    cond_nr = 0
    call_count = 0
    cond_nr = 0

def parse_fault_schedule(filename):
    file = open(filename,"r")

    fault_schedule = yaml.safe_load(file)

    nodes = parse_nodes(fault_schedule['nodes'])

    faults = parse_faults(fault_schedule['faults'],nodes)

    build_cfile(nodes,faults)

def parse_nodes(nodes):
    
    nodes_dict = {}
    node_nr = 0
    for key,value in nodes.items():
        nodes_dict[key] = createNode(key,value,node_nr)
        node_nr+=1

    return nodes_dict


def createNode(name,nodeconfig,node_nr):

    node = Node()

    node.name = name
    node.node_nr = node_nr

    keys = nodeconfig.keys()

    if 'pid' in keys:
        node.pid = nodeconfig['pid']

    if 'veth' in keys:
        node.veth = nodeconfig['veth']

    if 'ip' in keys:
        node.ip = nodeconfig['ip']

    if 'container_pid' in keys:
        node.container_pid = nodeconfig['container_pid']

    if 'script' in keys:
        node.script = nodeconfig['script']

    return node
    
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

        nodes = []

        for node in faultconfig['ips'].split():
            nodes.append(node)

        block_ips_fault.block_ips = nodes
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

            success = faultconfig['details']['success']
            
            if success == "True":
                file_system_operation_fault.success = 1
            else:
                file_system_operation_fault.success = 0
            file_system_operation_fault.return_value = faultconfig['details']['return_value']

            fault.fault_specifics = file_system_operation_fault

    if fault.type == "syscall":
        fault.fault_category = 2
        syscall_fault = syscall()
        syscall_fault.syscall_name = faultconfig['details']['name']
        syscall_fault.return_value = faultconfig['details']['return_value']

        fault.fault_specifics = syscall_fault

    if fault.type == "process_kill" or fault.type == "process_pause" or fault.type == "process_restart":
        fault.fault_category = 3

    if 'target' in faultconfig:
        fault.target = faultconfig['target']
        for name,node in nodes_dict.items():
            if name == fault.target:
                fault.target_nr = node.node_nr

    if 'repeatable' in faultconfig:

        repeatable = faultconfig['repeatable']

        if(repeatable == "True"):
            fault.repeatable = 1

    if 'duration' in faultconfig:
        fault.duration = faultconfig['duration']

    if 'occurrences' in faultconfig:
        fault.occurrences = faultconfig['occurrences']

    #fault.trigger_statement_begin = faultconfig['begin_conditions']['trigger_statement']

    begin_conditions = faultconfig['begin_conditions']
    
    fault.begin_conditions = []

    conditions_count = 0
    for name,condition in begin_conditions.items():
        if name == 'trigger_statement':
            continue

        if name == 'user_function':
            condition = build_user_function(condition)
            cond_nr = get_cond_type_nr(1,condition)
            # condition.cond_nr = cond_nr
            fault.begin_conditions.append(condition)

        if name == 'file_syscall':
            condition = build_file_syscall(condition)
            cond_nr = get_cond_type_nr(2,condition)
            condition.cond_nr = cond_nr
            fault.begin_conditions.append(condition)
        
        if name == "syscall":
            condition = build_syscall(condition)
            cond_nr = get_cond_type_nr(3,condition)
            condition.cond_nr = cond_nr
            fault.begin_conditions.append(condition)
        
        if name == "time":
            fault.begin_conditions.append(condition)

    if 'end_conditions' in faultconfig:
        fault.trigger_statement_end = faultconfig['end_conditions']['trigger_statement']

        end_conditions = faultconfig['end_conditions']

        conditions_count = 0
        for name,value in end_conditions.items():
            #todo
            continue

    return fault

def build_user_function(user_function_config):
    user_function = user_function_condition()

    user_function.binary_location = user_function_config['binary_location']

    user_function.symbol = user_function_config['symbol']

    if 'arguments' in user_function_config:
        for argument in user_function_config['arguments']:
            user_function.arguments.append(argument)

    user_function.call_count = user_function_config['call_count']

    return user_function



def build_file_syscall(file_system_call_config):
    file_system_call = file_syscall()

    file_system_call.syscall_name = file_system_call_config['syscall_name']

    if 'directory_name' in file_system_call_config:
        file_system_call.directory_name = file_system_call_config['directory_name']

    if 'file_name' in file_system_call_config:
        file_system_call.file_name = file_system_call_config['file_name']

    file_system_call.call_count = file_system_call_config['call_count']

    return file_system_call

def build_syscall(syscall_config):
    syscall = syscall_condition()

    syscall.syscall_name = syscall_config["syscall_name"]

    syscall.call_count = syscall_config["call_count"]

    return syscall

def build_cfile(nodes,faults):

    file = open('faultschedule.c','w+')

    file_template = open('faultschedule_template.c').read()
    file_template = file_template.replace("#node_count",str(len(nodes.items())))

    fault_count = calculate_fault_count(faults)
    file_template = file_template.replace("#fault_count",str(fault_count))

    file.write(file_template)
    build_nodes_cfile(file,nodes)
    build_faults_cfile(file,nodes,faults)
    return 0

def calculate_fault_count(faults):
    fault_count = 0
    for name,fault in faults.items():
        if fault.type == "network_partition":
            for name,partition in fault.fault_specifics.network_partitions.items():
                fault_count += len(partition)
        else:
            fault_count+=1
    return fault_count

def build_nodes_cfile(file,nodes):

    build_nodes_begin = """\nnode* build_nodes(){\n"""
    file.write(build_nodes_begin)

    build_nodes_malloc = """    node* nodes = ( node*)malloc(NODE_COUNT * sizeof(node));\n"""
    build_nodes_malloc = build_nodes_malloc.replace('#size',str(len(nodes.items())))
    file.write(build_nodes_malloc)
    
    node_nr = 0
    for name,node in nodes.items():
        build_node = """    create_node(&nodes[#nodenr],"#name",#pid,"#veth","#ip","#script");\n"""
        build_node = build_node.replace("#nodenr",str(node_nr))
        build_node = build_node.replace("#name",node.name)
        build_node = build_node.replace("#veth",node.veth)
        build_node = build_node.replace("#ip",node.ip)
        build_node = build_node.replace("#script",node.script)
        build_node = build_node.replace("#pid",str(node.pid))

        file.write(build_node)
        node_nr+=1
    
    build_nodes_end= """
    return nodes;
}"""
    file.write(build_nodes_end)



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

            fault_details = build_fault_details(fault.type,fault_type_nr,fault_count,fault.fault_specifics,nodes,"")

            file.write(fault_details)
            build_fault = """    create_fault(&faults[#faultnr],"#name",#target,#faulttype,#fault_category,fault_details#fault_nr,#repeat,#occurrences,#duration,#condition_count);\n\n"""

            build_fault = build_fault.replace("#faultnr",str(fault_count))
            build_fault = build_fault.replace("#name",fault.name)
            build_fault = build_fault.replace("#target",str(fault.target_nr))

            build_fault = build_fault.replace("#faulttype",str(fault_type_nr))

            build_fault = build_fault.replace("#fault_category",str(fault.fault_category))
            build_fault = build_fault.replace("#fault_nr",str(fault_count))
            build_fault = build_fault.replace("#repeat",str(fault.repeatable))
            build_fault = build_fault.replace("#occurrences",str(fault.occurrences))
            build_fault = build_fault.replace("#duration",str(fault.duration))
            build_fault = build_fault.replace("#condition_count",str(len(fault.begin_conditions)))
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
                build_fault = """    create_fault(&faults[#faultnr],"#name",#target,#faulttype,#fault_category,fault_details#fault_nr,#repeat,#occurrences,#duration,#condition_count);\n\n"""

                build_fault = build_fault.replace("#faultnr",str(fault_count))
                build_fault = build_fault.replace("#name","block_ips")
                build_fault = build_fault.replace("#target",str(target_nr))

                build_fault = build_fault.replace("#faulttype",str(fault_type_nr))
                build_fault = build_fault.replace("#fault_category",str(fault.fault_category))

                build_fault = build_fault.replace("#fault_nr",str(fault_count))
                build_fault = build_fault.replace("#repeat",str(fault.repeatable))
                build_fault = build_fault.replace("#occurrences",str(fault.occurrences))
                build_fault = build_fault.replace("#duration",str(fault.duration))
                build_fault = build_fault.replace("#condition_count",str(len(fault.begin_conditions)))

                file.write(build_fault)

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
            ip_count = 0
            for name in fault_specifics.block_ips:
                add_ip_block_line = """    add_ip_to_block_extra(&block_ips#nr,"#ipname",#ipnr);\n"""

                ip = nodes[name].ip
                add_ip_block_line = add_ip_block_line.replace("#nr",str(fault_nr))
                add_ip_block_line = add_ip_block_line.replace("#ipname",str(ip))
                add_ip_block_line = add_ip_block_line.replace("#ipnr",str(ip_count))
                block_ips_definition = block_ips_definition + add_ip_block_line
                ip_count+=1


            assign_line = """    fault_details#nr.block_ips = block_ips#nr;\n"""
            assign_line += """    fault_details#nr.block_ips.count = #ip_count;\n"""

            assign_line = assign_line.replace("#ip_count",str(ip_count))
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
                add_ip_block_line = """    add_ip_to_block_extra(&block_ips#nr,"#ipname",#ipnr);\n"""

                ip = nodes[name].ip
                add_ip_block_line = add_ip_block_line.replace("#nr",str(fault_nr))
                add_ip_block_line = add_ip_block_line.replace("#ipname",str(ip))
                add_ip_block_line = add_ip_block_line.replace("#ipnr",str(ip_count))
                block_ips_definition = block_ips_definition + add_ip_block_line
                ip_count+=1

            assign_line = """    fault_details#nr.block_ips = block_ips#nr;\n"""
            assign_line += """    fault_details#nr.block_ips.count = #ip_count;\n"""
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

            if len(fault_specifics.directory_name) > 0:
                file_sys_op += """    strcpy(file_syscall#nr.directory_name,"#directory_name");\n"""
                file_sys_op = file_sys_op.replace("#directory_name",fault_specifics.directory_name)
            if len(fault_specifics.file_name) > 0:
                file_sys_op += """    strcpy(file_syscall#nr.file_name,"#file_name");\n"""
                file_sys_op = file_sys_op.replace("#file_name",fault_specifics.file_name)


            file_sys_op += """    file_syscall#nr.success = #success;\n"""
            file_sys_op = file_sys_op.replace("#success",str(fault_specifics.success))
            file_sys_op += """    file_syscall#nr.return_value = #return_value;\n"""
            file_sys_op = file_sys_op.replace("#return_value",str(fault_specifics.return_value))
            file_sys_op += """    fault_details#nr.file_system_op = file_syscall#nr;\n"""
            file_sys_op = file_sys_op.replace("#nr",str(fault_nr))

            return file_sys_op

def build_fault_conditions(file,fault_nr,begin_conditions):
    condition_counter = 0
    for condition in begin_conditions:
        if isinstance(condition,syscall_condition):
            fault_condition = """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            fault_condition += """    systemcall syscall_#faultnr_#condnr;\n"""
            fault_condition += """    fault_condition_#faultnr_#condnr.type = SYSCALL;\n"""
            fault_condition += """    build_syscall(&syscall_#faultnr_#condnr,#syscall_nr,#call_count);\n"""
            fault_condition = fault_condition.replace("#syscall_nr",str(condition.cond_nr))
            fault_condition = fault_condition.replace("#call_count",str(condition.call_count))
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.syscall = syscall_#faultnr_#condnr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""
            fault_condition = fault_condition.replace("#faultnr",str(fault_nr))
            fault_condition = fault_condition.replace("#condnr",str(condition_counter))
            file.write(fault_condition)

        if isinstance(condition,file_syscall):
            fault_condition = """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            fault_condition += """    file_system_call file_syscall_#faultnr_#condnr;\n"""
            fault_condition += """    fault_condition_#faultnr_#condnr.type = FILE_SYSCALL;\n"""
            fault_condition += """    build_file_syscall(&file_syscall_#faultnr_#condnr,#syscall_nr,"#dir_name","#file_name",#call_count);\n"""
            fault_condition = fault_condition.replace("#syscall_nr",str(condition.cond_nr))
            fault_condition = fault_condition.replace("#dir_name",condition.directory_name)
            fault_condition = fault_condition.replace("#file_name",condition.file_name)
            fault_condition = fault_condition.replace("#call_count",str(condition.call_count))
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.file_system_call = file_syscall_#faultnr_#condnr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""
            fault_condition = fault_condition.replace("#faultnr",str(fault_nr))
            fault_condition = fault_condition.replace("#condnr",str(condition_counter))
            file.write(fault_condition)
        if isinstance(condition,user_function_condition):
            fault_condition = """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            fault_condition += """    user_function user_func_#faultnr_#condnr;\n"""
            fault_condition += """    fault_condition_#faultnr_#condnr.type = USER_FUNCTION;\n"""
            fault_condition += """    build_user_function(&user_func_#faultnr_#condnr,"#binary_location","#location",#call_count);\n"""
            fault_condition = fault_condition.replace("#binary_location",condition.binary_location)
            fault_condition = fault_condition.replace("#location",condition.symbol)
            fault_condition = fault_condition.replace("#call_count",str(condition.call_count))
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.user_function = user_func_#faultnr_#condnr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""
            fault_condition = fault_condition.replace("#faultnr",str(fault_nr))
            fault_condition = fault_condition.replace("#condnr",str(condition_counter))
            
            file.write(fault_condition)
        if isinstance(condition,int):
            fault_condition = """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            fault_condition += """    int time_#faultnr_#condnr = #time;\n"""
            fault_condition = fault_condition.replace("#time",str(condition))
            fault_condition += """    fault_condition_#faultnr_#condnr.type = TIME;\n"""
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.time = time_#faultnr_#condnr;\n"""        
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""

            fault_condition = fault_condition.replace("#faultnr",str(fault_nr))
            fault_condition = fault_condition.replace("#condnr",str(condition_counter))
            file.write(fault_condition)
        condition_counter+=1
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
        case "file_system_operation":
            match fault_specifics.syscall_name:
                case "write_file":
                    return 8
                case "read_file":
                    return 9
                case "mkdir":
                    return 23
                case "newfstatat":
                    return 24
                case "openat":
                    return 25
                case "open":
                    return 20
    return 0

def get_cond_type_nr(type,condition):
    match type:
        case 1:
            return 0
        case 2:
            match condition.syscall_name:
                case "openat":
                    return 20
                case "newfstatat":
                    return 19
        case 3:
            match condition.syscall_name:
                case "process_start":
                    return 0
                case "process_end":
                    return 1
                case "files_open":
                    return 2
                case "files_close":
                    return 3
                case "write":
                    return 6
                case "read":
                    return 7
                case "threads":
                    return 8
                case "open":
                    return 13
                case "mkdir":
                    return 14
                case "newfstatat":
                    return 15
                case "openat":
                    return 16
        case 4:
            return 21

def main():
    filename = sys.argv[1]

    parse_fault_schedule(filename)

if __name__ == "__main__":
    main()