# Types of conditions
class user_function_condition:
    binary_location = ""
    symbol = ""
    arguments = []
    absolute_offset = False
    offset = 0
    call_count = 0

    def to_yaml(self):
        return {
            "type": "user_function",
            "binary_location": str(self.binary_location),
            "symbol": str(self.symbol),
            "offset": str(self.offset),
            "absolute_offset": self.absolute_offset,
            "call_count": str(self.call_count),
        }


class file_syscall_condition:
    syscall_name = ""
    cond_nr = 0
    file_name = ""
    call_count = 0
    cond_nr = 0

    def to_yaml(self):
        return {
            "type": "file_syscall",
            "syscall_name": str(self.syscall_name),
            "file_name": str(self.file_name),
            "call_count": str(self.call_count),
        }


class syscall_condition:
    syscall_name = ""
    cond_nr = 0
    call_count = 0
    cond_nr = 0

    def to_yaml(self):
        return {
            "type": "syscall",
            "syscall_name": str(self.syscall_name),
            "call_count": str(self.call_count),
        }


class time_cond:
    time = 0

    def to_yaml(self):
        return {"type": "time", "time": int(self.time)}


class fault_dependency_condition:
    name = ""     # fault name — resolved to fault_nr before codegen
    fault_nr = -1

    def to_yaml(self):
        return {"type": "fault_condition", "name": self.name}


def build_fault_condition(config):
    cond = fault_dependency_condition()
    cond.name = config["name"]
    return cond


def build_time(time_config):
    time = time_cond()

    time.time = time_config["time"]

    return time


def build_user_function(user_function_config):
    user_function = user_function_condition()

    user_function.binary_location = user_function_config["binary_location"]

    user_function.symbol = user_function_config["symbol"]

    if "arguments" in user_function_config:
        for argument in user_function_config["arguments"]:
            user_function.arguments.append(argument)

    user_function.call_count = user_function_config["call_count"]

    if "offset" in user_function_config:
        user_function.offset = int(user_function_config["offset"])

    if "absolute_offset" in user_function_config:
        user_function.absolute_offset = user_function_config["absolute_offset"]

    return user_function


def build_file_syscall(file_system_call_config):
    file_system_call = file_syscall_condition()

    if "syscall_name" in file_system_call_config:
        file_system_call.syscall_name = file_system_call_config["syscall_name"]
    else:
        print("Missing syscall_name in", file_system_call_config)
        exit(1)

    if "file_name" in file_system_call_config:
        file_system_call.file_name = file_system_call_config["file_name"]
    else:
        print("Missing file_name in", file_system_call_config)
        exit(1)

    file_system_call.call_count = file_system_call_config["call_count"]

    return file_system_call


def build_syscall(syscall_config):
    syscall = syscall_condition()

    syscall.syscall_name = syscall_config["syscall_name"]

    syscall.call_count = syscall_config["call_count"]

    return syscall


def build_fault_conditions(file, fault_nr, begin_conditions):
    condition_counter = 0
    for condition in begin_conditions:
        if isinstance(condition, syscall_condition):
            fault_condition = (
                """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            )
            fault_condition += """    system_call syscall_#faultnr_#condnr;\n"""
            fault_condition += (
                """    fault_condition_#faultnr_#condnr.type = SYSCALL;\n"""
            )
            fault_condition += """    build_syscall(&syscall_#faultnr_#condnr,#syscall_nr,#call_count);\n"""
            fault_condition = fault_condition.replace(
                "#syscall_nr", str(condition.cond_nr)
            )
            fault_condition = fault_condition.replace(
                "#call_count", str(condition.call_count)
            )
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.syscall = syscall_#faultnr_#condnr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""
            fault_condition = fault_condition.replace("#faultnr", str(fault_nr))
            fault_condition = fault_condition.replace("#condnr", str(condition_counter))
            file.write(fault_condition)

        if isinstance(condition, file_syscall_condition):
            fault_condition = (
                """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            )
            fault_condition += (
                """    file_system_call file_syscall_#faultnr_#condnr;\n"""
            )
            fault_condition += (
                """    fault_condition_#faultnr_#condnr.type = FILE_SYSCALL;\n"""
            )
            fault_condition += """    build_file_syscall(&file_syscall_#faultnr_#condnr,#syscall_nr,"#file_name",#call_count);\n"""
            fault_condition = fault_condition.replace(
                "#syscall_nr", str(condition.cond_nr)
            )
            fault_condition = fault_condition.replace("#file_name", condition.file_name)
            fault_condition = fault_condition.replace(
                "#call_count", str(condition.call_count)
            )
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.file_system_call = file_syscall_#faultnr_#condnr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""
            fault_condition = fault_condition.replace("#faultnr", str(fault_nr))
            fault_condition = fault_condition.replace("#condnr", str(condition_counter))
            file.write(fault_condition)
        if isinstance(condition, user_function_condition):
            fault_condition = (
                """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            )
            fault_condition += """    user_function user_func_#faultnr_#condnr;\n"""
            fault_condition += (
                """    fault_condition_#faultnr_#condnr.type = USER_FUNCTION;\n"""
            )
            fault_condition += """    build_user_function(&user_func_#faultnr_#condnr,"#binary_location","#location",#call_count,#offset,#absolute_offset);\n"""
            fault_condition = fault_condition.replace(
                "#binary_location", condition.binary_location
            )
            fault_condition = fault_condition.replace("#location", condition.symbol)
            fault_condition = fault_condition.replace(
                "#call_count", str(condition.call_count)
            )
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.user_function = user_func_#faultnr_#condnr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""
            fault_condition = fault_condition.replace("#faultnr", str(fault_nr))
            fault_condition = fault_condition.replace("#condnr", str(condition_counter))
            fault_condition = fault_condition.replace("#offset", str(condition.offset))

            if condition.absolute_offset:
                fault_condition = fault_condition.replace("#absolute_offset", "true")
            else:
                fault_condition = fault_condition.replace("#absolute_offset", "false")

            file.write(fault_condition)
        if isinstance(condition, time_cond):
            fault_condition = (
                """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            )
            fault_condition += """    int time_#faultnr_#condnr = #time;\n"""
            fault_condition = fault_condition.replace("#time", str(condition.time))
            fault_condition += """    fault_condition_#faultnr_#condnr.type = TIME;\n"""
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.time = time_#faultnr_#condnr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""

            fault_condition = fault_condition.replace("#faultnr", str(fault_nr))
            fault_condition = fault_condition.replace("#condnr", str(condition_counter))
            file.write(fault_condition)
        if isinstance(condition, fault_dependency_condition):
            fault_condition = """    fault_condition fault_condition_#faultnr_#condnr;\n"""
            fault_condition += """    fault_condition_#faultnr_#condnr.type = FAULT_CONDITION;\n"""
            fault_condition += """    fault_condition_#faultnr_#condnr.condition.fault_dep.fault_nr = #dep_fault_nr;\n"""
            fault_condition += """    add_begin_condition(&faults[#faultnr],fault_condition_#faultnr_#condnr,#condnr);\n"""
            fault_condition = fault_condition.replace("#dep_fault_nr", str(condition.fault_nr))
            fault_condition = fault_condition.replace("#faultnr", str(fault_nr))
            fault_condition = fault_condition.replace("#condnr", str(condition_counter))
            file.write(fault_condition)
        condition_counter += 1


def get_cond_type_nr(type, condition):
    match type:
        case 1:
            return 0
        case 2:
            match condition.syscall_name:
                case "openat":
                    return "OPENAT_SPECIFIC"
                case "newfstatat":
                    return "NEWFSTATAT_FILE_STATE"
                case "write":
                    return 22
                case "fdatasync":
                    return "FDATASYNC_FILE_STATE"
                case "fsync":
                    return "FSYNC_STATE"
                case "read":
                    return "READ_FILE"
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
                    return "NEWFSTATAT_STATE"
                case "openat":
                    return "OPENNAT_STATE"
                case "fdatasync":
                    return "FDATASYNC_STATE"
                case "fsync":
                    return "FSYNC_STATE"
                case "pwrite64":
                    return "PWRITE64_STATE"
                case "accept":
                    return "ACCEPT_STATE"
                case "close":
                    return "CLOSE_STATE"
                case "futex":
                    return "FUTEX_STATE"
                case "connect":
                    return "CONNECT_STATE"
                case "stat":
                    return "STAT_STATE"
                case "lstat":
                    return "LSTAT_STATE"
                case "rename":
                    return "RENAME_STATE"
                case "lseek":
                    return "LSEEK_STATE"
                case "unlink":
                    return "UNLINK_STATE"
                case "sync_file_range":
                    return "SYNC_FILE_RANGE_STATE"
                case "bind":
                    return "BIND_STATE"
                case "clone":
                    return "CLONE_STATE"
                case "dup":
                    return "DUP_STATE"
                case "mmap":
                    return "MMAP_STATE"
                case "epoll_create1":
                    return "EPOLL_CREATE1_STATE"
                case "epoll_ctl":
                    return "EPOLL_CTL_STATE"
                case "epoll_pwait":
                    return "EPOLL_PWAIT_STATE"
                case "eventfd2":
                    return "EVENTFD2_STATE"
                case "fcntl":
                    return "FCNTL_STATE"
                case "flock":
                    return "FLOCK_STATE"
                case "fstat":
                    return "FSTAT_STATE"
                case "ftruncate":
                    return "FTRUNCATE_STATE"
                case "getdents64":
                    return "GETDENTS64_STATE"
                case "getpeername":
                    return "GETPEERNAME_STATE"
                case "getsockname":
                    return "GETSOCKNAME_STATE"
                case "ioctl":
                    return "IOCTL_STATE"
                case "listen":
                    return "LISTEN_STATE"
                case "madvise":
                    return "MADVISE_STATE"
                case "mkdirat":
                    return "MKDIRAT_STATE"
                case "mprotect":
                    return "MPROTECT_STATE"
                case "pipe":
                    return "PIPE_STATE"
                case "prctl":
                    return "PRCTL_STATE"
                case "sched_getaffinity":
                    return "SCHED_GETAFFINITY_STATE"
                case "socket":
                    return "SOCKET_STATE"
                case "statfs":
                    return "STATFS_STATE"
                case "tgkill":
                    return "TGKILL_STATE"
                case "unlinkat":
                    return "UNLINKAT_STATE"
                case "msync":
                    return "MSYNC_STATE"
                case "renameat":
                    return "RENAMEAT_STATE"
                case "execve":
                    return "EXECVE_STATE"
                case "accept4":
                    return "ACCEPT4_STATE"
        case 4:
            return 21
