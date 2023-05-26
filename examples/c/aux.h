#ifndef __AUX_H_
#define __AUX_H_

#define MAX_ENTRIES 10240
#define PATH_MAX	4096
#define STATE_PROPERTIES_COUNT 6
#define MAX_IPS_BLOCKED 16
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct aux_bpf* start_aux_maps();
int get_interface_index(char*);
struct fault {
    __u64 syscall;
    //array with conditions
    __u64 *fault_type_conditions;
    int *conditions_match;
    __be32 ips_blocked[MAX_IPS_BLOCKED];
    char *veth;
};

//syscall to fail
enum syscall{
    FORK = 1,
    WRITE = 2,
    READ = 3,
    NETWORK_ISOLATION = 4,
    BLOCK_IPS = 5,
    TEMP_EMPTY = 999
};

//Positions of array which correspond to a certain counter
enum stateinfo{
    PROCESSES_OPENED = 0,
    PROCESSES_CLOSED = 1,
    FILES_OPENED = 2,
    FILES_CLOSED = 3,
    WRITES = 4
};

//To process different types of events in userspace
enum eventype{
    EXEC_EXIT = 0,
    WRITE_HOOK = 1,
    TC = 2
};

struct event {
	int type;
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	__u64 processes_created;
	__u64 processes_closed;
    __u64 writes;
    __u32 ip_proto;
    __u32 ifindex;
	__be32 src_addr;
	__be32 dst_addr;
};

#endif /* __AUX_H */