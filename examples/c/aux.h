#ifndef __AUX_H_
#define __AUX_H_

#define MAX_ENTRIES 10240
#define PATH_MAX	4096
#define STATE_PROPERTIES_COUNT 12
#define MAX_IPS_BLOCKED 16
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128
#define FUNCNAME_MAX 16
#define MAX_FUNCTIONS 8
#define FILENAME_MAX 64
#define FAULTSSUPPORTED 7

struct fault {
    __u64 faulttype;
    //I do not remember what this was for
    int *faulttype_count;
    __be32 ips_blocked[MAX_IPS_BLOCKED];
    char *veth;
    char file_open[FILENAME_MAX];
    char func_names[8][FUNCNAME_MAX];
    int done;
    struct faultstate *initial;
    struct faultstate *end;
    int pid;
    int repeat;
    int occurrences;
};

struct fault_key{
    int pid;
    int faulttype;
};

struct fault_description{
    int on;
    int occurences;
};

struct info_key{
    int pid;
    int infotype;
};

struct info_state{
    __u64 relevant_states[256];
    __u64 current_value;
    int repeat;
};

struct faultstate{
    __u64 *fault_type_conditions;
    int *conditions_match;
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
    THREADS_CREATED = 11 
};

//To process different types of events in userspace
enum eventype{
    EXEC = 0,
    EXIT = 7,
    WRITE_HOOK = 1,
    READ_HOOK = 4,
    TC = 2,
    FSYS = 3,
    THREAD = 5,
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
	__u64 processes_created;
    __u64 processes_created_repeat;
	__u64 processes_closed;
    __u64 processes_closed_repeat;
    __u64 writes;
    __u64 writes_repeat;
    __u64 reads;
    __u64 reads_repeat;
    __u32 ip_proto;
    __u32 ifindex;
	__be32 src_addr;
	__be32 dst_addr;
};

struct aux_bpf* start_aux_maps();
int get_interface_index(char*);
void build_fault(struct fault* ,int,int,int);
void add_ip_to_block(struct fault*,char *,int);
void set_if_name(struct fault*,char *);
void add_function_to_monitor(struct fault*,char*,int);
int bpf_map_lookup_or_try_init_user(int, const void *, void *,void *);
int get_interface_names(char **,int);
#endif /* __AUX_H */