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
    // Optional baseline network latency (not a fault - see
    // apply_node_latency() in executor.c). 0 = disabled.
    int latency_ms;
    int jitter_ms;
}node;


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
    // Params forwarded verbatim (when non-empty) as `key=value` segments of the
    // `lazyfs::<cmd>::...` pipe command - see executor.c's TORN_OP/TORN_SEQ/
    // CRASH_FS cases. file/op/persist/parts/parts_bytes are used by LazyFS's
    // torn-op/torn-seq protocol. from_rgx/to_rgx are CRASH_FS-only: they give
    // LazyFS's `crash` fault regex-based path targeting (matching a filename
    // pattern instead of a literal path, for when the exact path being
    // written isn't known ahead of time, e.g. apps that write to a generated
    // temp filename before renaming it) - LazyFS's torn-op/torn-seq fifo
    // commands do not accept from_rgx/to_rgx at all and reject the whole
    // fault with an "unknown attribute" error if sent, so executor.c must
    // never forward these two fields for TORN_OP/TORN_SEQ.
    char file[STRING_SIZE];
    char fs_op[STRING_SIZE];
    char persist[STRING_SIZE];
    char parts[STRING_SIZE];
    char parts_bytes[STRING_SIZE];
    char from_rgx[STRING_SIZE];
    char to_rgx[STRING_SIZE];
}lazyfs_fault;

typedef struct partial_write_fault{
    // Bytes to truncate the target's next write() to - forwarded verbatim to
    // rose.ko's `partial_count` module parameter. See executor.c's
    // PARTIAL_WRITE_FAULT case.
    int count;
    // 0 (default): truncate the syscall's count only, buf is left untouched -
    // a genuine short write, where a correctly-retrying caller recovers the
    // full, correct data. 1: also poison buf[count:orig_count) with 0xEE
    // (rose.c's corrupt_write_tail) - a "correct" retry from the same buffer
    // still persists garbage. See rose.c's write_pre_handler.
    int corrupt_buffer;
}partial_write_fault;

typedef struct partial_read_fault{
    // Bytes to truncate the target's next read() to - forwarded verbatim to
    // rose.ko's `partial_read_count` module parameter. Buffer beyond that
    // count is left untouched - a genuine short read. See rose.c's
    // read_pre_handler.
    int count;
}partial_read_fault;

typedef struct torn_read_fault{
    // Offset within the *actually returned* bytes of the target's next
    // read() to start poisoning with 0xEE from - forwarded verbatim to
    // rose.ko's `torn_read_offset` module parameter. read() still reports
    // its real, full success count - only the data is silently wrong. See
    // rose.c's torn_read_ret_handler.
    int offset;
}torn_read_fault;

typedef union fault_details{
    syscall_operation syscall;
    block_ips block_ips;
    packet_drop packet_drop;
    process_fault process_fault;
    lazyfs_fault lazyfs_fault;
    partial_write_fault partial_write_fault;
    partial_read_fault partial_read_fault;
    torn_read_fault torn_read_fault;
}fault_details;

enum fault_categories{
    NETWORK = 0,
    PROCESS = 1,
    SYSCALL_FAULT = 2,
    LAZYFS = 4,
    KERNEL_FAULT = 5,

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
void create_node(node* node, char* name,int pid,char* pid_file, char* veth, char* ip, char* script,char* env,int container,int container_type,char* binary,char *leader_symbol,int leader,int latency_ms,int jitter_ms);

int get_maximum_time();
node* build_nodes();
int get_node_count();
fault* build_faults_extra();
int get_fault_count();
execution_plan* build_execution_plan();
tracer* build_tracer();
#endif /* __FAULTS_SCHEDULE_H */
