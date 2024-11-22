#ifndef __FAULTSCHEDULE_H_
#define __FAULTSCHEDULE_H_
#define STRING_SIZE 128
#define MAX_ENTRIES 10240
#define PATH_MAX	4096
#define STATE_PROPERTIES_COUNT 22
#define MAX_IPS_BLOCKED 16
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128
#define FUNCNAME_MAX 512
#define MAX_FUNCTIONS 32
#define FILENAME_MAX 64
#define FAULTSSUPPORTED 21
#define MAX_RELEVANT_FILES 256
#define MAX_ARGS 16
#define MAX_FAULTS 32

typedef struct Tracer{

    char tracer_location[STRING_SIZE];
    char pipe_location[STRING_SIZE];
    char functions_file[STRING_SIZE];
    char binary_path[STRING_SIZE];
    int pipe_write_end;
    int pid;

}tracer;

typedef struct Setup{
    char script[STRING_SIZE];
    int duration;
    int pid;
}setup;

typedef struct Workload{
    char script[STRING_SIZE];
    int pid;
}workload;

typedef struct Cleanup{
    char script[STRING_SIZE];
    int pid;
    int duration; //This is not how long it takes to cleanup, but the amount of time we should wait for the last fault to take effect
}cleanup;

typedef struct Execution_Plan{
    setup setup;
    workload workload;
    cleanup cleanup;
}execution_plan;

typedef struct Node {
    char name[STRING_SIZE];
    //pid is the first pid we initiliazed faults with
    int pid;
    //current_pid will hold the nodes current pid usefull for process_kills
    int current_pid;
    char veth[STRING_SIZE];
    char ip[STRING_SIZE];
    char script[STRING_SIZE];
    char env[STRING_SIZE];
    char binary[STRING_SIZE];
    char leader_symbol[STRING_SIZE];
    int pid_tc_in;
    int pid_tc_out;
    int container;
    int container_pid;
    struct uprobes_bpf *leader_probe;
    int leader;
    int running;
    char **args;
    int if_index;
}node;


typedef struct file_system_operation{
    int syscall;
    int syscall_condition;
    char file_name[STRING_SIZE];
    char directory_name[STRING_SIZE];
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

typedef union fault_details{
    file_system_operation file_system_op;
    syscall_operation syscall;
    block_ips block_ips;
    packet_drop packet_drop;
    process_fault process_fault;
}fault_details;

enum fault_categories{
    NETWORK = 0,
    PROCESS = 1,
    SYSCALL_FAULT = 2,
    FILE_SYS_OP = 3

};

typedef struct user_function{
    char binary_location[STRING_SIZE];
    char symbol[FUNCNAME_MAX];
    //TODO arguments
    int call_count;
    int cond_nr;
    int offset;
}user_function;

typedef struct file_system_call{
    int syscall;
    char directory_name[STRING_SIZE];
    char file_name[STRING_SIZE];
    int success;
    int call_count;
}file_system_call;

typedef struct systemcall{
    int syscall;
    int call_count;
}systemcall;

typedef struct fault_condition{
    int type;
    union condition{
        user_function user_function;
        file_system_call file_system_call;
        systemcall syscall;
        int time;
    } condition;
}fault_condition;

enum condition_types{
    USER_FUNCTION = 1,
    FILE_SYSCALL = 2,
    SYSCALL = 3,
    TIME = 4

};

struct faultstate{
    int fault_type_conditions[STATE_PROPERTIES_COUNT];
    int conditions_match[STATE_PROPERTIES_COUNT];
};

typedef struct fault {
    char name[STRING_SIZE];
    int target;
    int traced;
    int category;
    int faulttype;
    int done;
    fault_details fault_details;
    fault_condition *fault_conditions_begin;
    fault_condition *fault_conditions_end;

    //trigger_statement_begin
    //trigger_statement_end

    __be32 ips_blocked[MAX_IPS_BLOCKED];
    char *veth;
    char file_open[FILENAME_MAX];
    char func_names[MAX_FUNCTIONS][FUNCNAME_MAX];
    struct uprobes_bpf *list_of_functions[MAX_FUNCTIONS];

    struct faultstate initial;
    struct faultstate end;
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



void create_node(node* node, char* name,int pid, char* veth, char* ip, char* script,char* env,int container,char* binary,char *leader_symbol,int leader);
void add_ip_to_block(struct fault*,char *,int);

node* build_nodes();
int get_node_count();

fault* build_faults_extra();
int get_fault_count();

execution_plan* build_execution_plan();

tracer* build_tracer();
#endif /* __FAULTSCHEDULE_H */
