#Types of conditions
class user_function_condition:
    binary_location = ""
    symbol = ""
    arguments = []
    offset = 0
    call_count = 0

    def to_yaml(self):
        return {"type":"user_function","binary_location":str(self.binary_location),"symbol":str(self.symbol),"offset":str(self.offset),"call_count":str(self.call_count)}

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

class time_cond:
    time = 0

    def to_yaml(self):
        return {"type":"time","time":str(self.time)}

def build_time(time_config):
    time = time_cond()

    time.time = time_config['time']

    return time

def build_user_function(user_function_config):
    user_function = user_function_condition()

    user_function.binary_location = user_function_config['binary_location']

    user_function.symbol = user_function_config['symbol']

    if 'arguments' in user_function_config:
        for argument in user_function_config['arguments']:
            user_function.arguments.append(argument)

    user_function.call_count = user_function_config['call_count']

    if 'offset' in user_function_config:
        user_function.offset = int(user_function_config['offset'])

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
            fault_condition += """    build_user_function(&user_func_#faultnr_#condnr,"#binary_location","#location",#call_count,#offset);\n"""
            fault_condition = fault_condition.replace("#binary_location",condition.binary_location)
            fault_condition = fault_condition.replace("#location",condition.symbol)
            fault_condition = fault_condition.replace("#call_count",str(condition.call_count))
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.user_function = user_func_#faultnr_#condnr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""
            fault_condition = fault_condition.replace("#faultnr",str(fault_nr))
            fault_condition = fault_condition.replace("#condnr",str(condition_counter))
            fault_condition = fault_condition.replace("#offset",str(condition.offset))
            
            file.write(fault_condition)
        if isinstance(condition,time_cond):
            fault_condition = """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            fault_condition += """    int time_#faultnr_#condnr = #time;\n"""
            fault_condition = fault_condition.replace("#time",str(condition.time))
            fault_condition += """    fault_condition_#faultnr_#condnr.type = TIME;\n"""
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.time = time_#faultnr_#condnr;\n"""        
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""

            fault_condition = fault_condition.replace("#faultnr",str(fault_nr))
            fault_condition = fault_condition.replace("#condnr",str(condition_counter))
            file.write(fault_condition)
        condition_counter+=1

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
                case "write":
                    return 22
                case "fdatasync":
                    return "FDATASYNCFILE_STATE"
                case "fsync":
                        return "FSYNC_STATE"
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
                case "fdatasync":
                    return "FDATASYNC_STATE"
                case "fsync":
                    return "FSYNC_STATE"
        case 4:
            return 21