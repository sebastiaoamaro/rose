#ifndef __FAULTS_SCHEDULE_H_
#define __FAULTS_SCHEDULE_H_
#include "bpf_shared.h"
// STRING_SIZE and FUNCNAME_MAX are sized specifically for the structs below
// (larger than aux.h's copies) and are the canonical definitions for these
// names; every other size macro here that's also defined in aux.h is unused
// in this file, so it's left solely in aux.h (consumers already include both
// headers). MAX_IPS_BLOCKED, STATE_PROPERTIES_COUNT and MAX_FUNCTIONS come
// from bpf_shared.h above instead of being redefined here, since the structs
// below need them and bpf_shared.h is guaranteed to already be included by
// the time this file is parsed.
#define STRING_SIZE 256
#define FUNCNAME_MAX 512
#define FILENAME_MAX 64

typedef struct Tracer{
    char tracer_location[STRING_SIZE];
    char pipe_location[STRING_SIZE];
    char functions_file[STRING_SIZE];
    char binary_path[STRING_SIZE];
    int pipe_write_end;
    int pipe_read_end;
    int pid;
    char tracing_type[STRING_SIZE];

}tracer;

typedef struct Setup{
    char script[STRING_SIZE];
    int duration;
    int pid;
    FILE *read_end;
}setup;

typedef struct Pre_Workload{
    char script[STRING_SIZE];
    int pid;
    FILE *read_end;
}pre_workload;

typedef struct Workload{
    char script[STRING_SIZE];
    int pid;
    int wait_time;
    int wait_workload;
    FILE *read_end;
}workload;

typedef struct Cleanup{
    char script[STRING_SIZE];
    int pid;
    int duration; //This is not how long it takes to cleanup, but the amount of time we should wait for the last fault to take effect
}cleanup;

typedef struct LazyFS{
    char script[STRING_SIZE];
    char root_dir[STRING_SIZE];
    char mount_dir[STRING_SIZE];
    char pipe_location[STRING_SIZE];
    int pid;
    FILE *read_end;
}lazyfs;

typedef struct Execution_Plan{
    setup setup;
    pre_workload pre_workload;
    workload workload;
    cleanup cleanup;
    lazyfs lazyfs;
}execution_plan;

typedef struct Node {
    char name[STRING_SIZE];
    //pid is the first pid we initiliazed faults with
    int pid;
    //current_pid will hold the nodes current pid usefull for process_kills
    int current_pid;
    char pid_file[STRING_SIZE];
    char veth[STRING_SIZE];
    char ip[STRING_SIZE];
    char script[STRING_SIZE];
    char env[STRING_SIZE];
    char binary[STRING_SIZE];
    char leader_symbol[STRING_SIZE];
    int pid_tc_in;
    int pid_tc_out;
    int container;
    int container_type;
    int container_pid;
    struct uprobes_bpf *leader_probe;
    int leader;
    int running;
    char **args;
    int if_index;
    FILE *read_end;
}node;


typedef struct file_system_operation{
    int syscall;
    int syscall_condition;
    char file_name[STRING_SIZE];
    int success;
    int return_value;
}file_system_operation;

typedef struct syscall_operation{
    int syscall;
    int success;
    int return_value;
}syscall_operation;

typedef struct block_ips{
    int count_in;
    int count_out;
    __be32 nodes_in[MAX_IPS_BLOCKED];
    __be32 nodes_out[MAX_IPS_BLOCKED];
}block_ips;

typedef struct packet_drop{
    float percentage;
}packet_drop;

typedef struct process_fault{
    int type;
}process_fault;

typedef struct lazyfs_fault{
    int operation;
}lazyfs_fault;


typedef union fault_details{
    file_system_operation file_system_op;
    syscall_operation syscall;
    block_ips block_ips;
    packet_drop packet_drop;
    process_fault process_fault;
    lazyfs_fault lazyfs_fault;
}fault_details;

enum fault_categories{
    NETWORK = 0,
    PROCESS = 1,
    SYSCALL_FAULT = 2,
    FILE_SYS_OP = 3,
    LAZYFS = 4,

};

typedef struct user_function{
    char binary_location[STRING_SIZE];
    char symbol[FUNCNAME_MAX];
    int call_count;
    int cond_nr;
    int offset;
    int absolute_offset;
}user_function;

typedef struct file_system_call{
    int syscall;
    char directory_name[STRING_SIZE];
    char file_name[STRING_SIZE];
    int success;
    int call_count;
}file_system_call;

typedef struct system_call{
    int syscall;
    int call_count;
}system_call;

typedef struct fault_dependency{
    int fault_nr;
}fault_dependency;

typedef struct fault_condition{
    int type;
    union condition{
        user_function user_function;
        file_system_call file_system_call;
        system_call syscall;
        fault_dependency fault_dep;
        int time;
    } condition;
}fault_condition;

enum condition_types{
    USER_FUNCTION = 1,
    FILE_SYSCALL = 2,
    SYSCALL = 3,
    TIME = 4,
    FAULT_CONDITION = 5,
};

struct fault_state{
    int fault_type_conditions[STATE_PROPERTIES_COUNT];
    int conditions_match[STATE_PROPERTIES_COUNT];
};

typedef struct fault {
    char name[STRING_SIZE];
    int target;
    int traced;
    int category;
    int fault_type;
    int done;
    fault_details fault_details;
    fault_condition *fault_conditions_begin;
    fault_condition *fault_conditions_end;

    __be32 ips_blocked[MAX_IPS_BLOCKED];
    char *veth;
    char file_open[FILENAME_MAX];
    char func_names[MAX_FUNCTIONS][FUNCNAME_MAX];
    struct uprobes_bpf *list_of_functions[MAX_FUNCTIONS];

    struct fault_state initial;
    struct fault_state end;
    int pid;
    int repeat;
    int occurrences;
    int network_directions;
    int return_value;
    int container_pid;
    char **command;
    char binary_location[FUNCNAME_MAX];
    int faults_injected_counter;
    int relevant_conditions;
    int duration;
    int exit;
}fault;

// Defined by the generated fault_schedule.c (see schedule_parser/fault_schedule_template.c),
// not by the checked-in placeholder fault_schedule.c.
void create_node(node* node, char* name,int pid,char* pid_file, char* veth, char* ip, char* script,char* env,int container,int container_type,char* binary,char *leader_symbol,int leader);

int get_maximum_time();
node* build_nodes();
int get_node_count();
fault* build_faults_extra();
int get_fault_count();
execution_plan* build_execution_plan();
tracer* build_tracer();
#endif /* __FAULTS_SCHEDULE_H */
