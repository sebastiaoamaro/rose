#ifndef __AUX_H_
#define __AUX_H_

#define MAX_ENTRIES 10240
#define PATH_MAX	4096
#define STATE_PROPERTIES_COUNT 20
#define MAX_IPS_BLOCKED 16
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128
#define FUNCNAME_MAX 128
#define MAX_FUNCTIONS 8
#define FILENAME_MAX 64
#define FAULTSSUPPORTED 22
#define MAX_RELEVANT_FILES 256

struct fault {
    __u64 faulttype;
    //I do not remember what this was for
    int *faulttype_count;
    __be32 ips_blocked[MAX_IPS_BLOCKED];
    char *veth;
    char file_open[FILENAME_MAX];
    char func_names[MAX_FUNCTIONS][FUNCNAME_MAX];
    int done;
    struct faultstate *initial;
    struct faultstate *end;
    int pid;
    int repeat;
    int occurrences;
    int network_directions;
    int return_value;
    int container_pid;
    char **command;
    char *binary_location;
    int faults_injected_counter;
};

struct fault_key{
    int pid;
    int faulttype;
};

struct fault_description{
    int on;
    int occurences;
    int return_value;
    int syscall_nr;
};

struct info_key{
    int pid;
    //type of state_condition
    int infotype;
};

struct info_state{
    __u64 relevant_states[256];
    __u64 current_value;
    int repeat;
};

struct faultstate{
    int fault_type_conditions[STATE_PROPERTIES_COUNT];
    int *conditions_match;
};

struct relevant_fds{
    __u64 fds[MAX_RELEVANT_FILES];
    int size;
};

//syscall to fail, rename to faulttype
enum faulttype{
    FORK = 1,
    WRITE = 2,
    READ = 3,
    NETWORK_ISOLATION = 4,
    BLOCK_IPS = 5,
    DROP_PACKETS = 6,
    CLONE = 7,
    WRITE_FILE = 8,
    READ_FILE = 9,
    PROCESS_KILL = 11,
    WRITE_RET = 12,
    READ_RET = 13,
    STOP = 14,
    OPEN = 15,
    MKDIR = 16,
    NEWFSTATAT = 17,
    OPENAT = 18,
    NEWFSTATAT_RET = 19,
    VFSTATAT_FILE = 20,
    OPENAT_RET = 21,
    TEMP_EMPTY = 999,
};

//Positions of array which correspond to a certain counter
enum stateinfo{
    PROCESSES_OPENED = 0,
    PROCESSES_CLOSED = 1,
    FILES_OPENED = 2,
    FILES_CLOSED = 3,
    FILES_OPENED_ANY = 4,
    FILES_CLOSED_ANY = 5,
    WRITES = 6,
    READS = 7,
    IPS_BLOCKED = 8,
    FUNCNAMES = 9,
    CALLCOUNT = 10,
    THREADS_CREATED = 11,
    PROCESS_TO_KILL = 12,
    OPENS = 13,
    DIRCREATED =14,
    NEWFSTATAT_COUNT = 15,
    OPENNAT_COUNT = 16,
    VFS_FSTATAT_COUNT = 17,
    VFS_FSTATAT_SPECIFIC = 18,
    NEW_FSTATAT_SPECIFIC = 19
};

//TODO:To process different types of events in userspace, THIS CAN BE REFACTORED TO JUST BE THE SAME AS STATE_INFO
enum eventype{
    EXEC = 0,
    EXIT = 7,
    WRITE_HOOK = 1,
    READ_HOOK = 4,
    TC = 2,
    FSYS = 3,
    THREAD = 5,
    NEWFSTATAT_HOOK = 6,
    MKDIR_HOOK = 7,
    OPEN_HOOK = 8,
    OPENNAT_HOOK = 9,
    FUNCTIONS = 10,
    VFS_FSTATAT_HOOK = 11
};

enum generic{
    ANY_PID = 411
};

struct event {
	int type;
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
    __u64 state_condition;
    int syscall_nr;
    __u32 ip_proto;
    __u32 ifindex;
	__be32 src_addr;
	__be32 dst_addr;
};

struct aux_bpf* start_aux_maps();
int get_interface_index(char*);
void build_fault(struct fault* ,int,int,int,int,int,char**,int,char *);
void add_ip_to_block(struct fault*,char *,int);
void set_if_name(struct fault*,char *);
void add_function_to_monitor(struct fault*,char*,int);
int bpf_map_lookup_or_try_init_user(int, const void *, void *,void *);
int get_interface_names(char **,int);
int translate_pid(int);
#endif /* __AUX_H */