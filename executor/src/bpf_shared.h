#ifndef __BPF_SHARED_H_
#define __BPF_SHARED_H_
// Structs/enums here must stay byte-identical between the BPF programs
// (*.bpf.c / *.bpf.h) and the userspace loader (aux.c, main.c) since they're
// used as BPF map keys/values or ring buffer event payloads. Only put
// something here if a *.bpf.c file actually needs it - everything else
// belongs in aux.h.
#define STATE_PROPERTIES_COUNT 32
// fault_schedule.h includes this header to get MAX_IPS_BLOCKED, sizing
// fault.fault_details.block_ips the same as the blocked_ips BPF map value
// type (__be32[MAX_IPS_BLOCKED]) below.
#define MAX_IPS_BLOCKED 8
#define MAX_FUNCTIONS 32
#define MAX_RELEVANT_FILES 16
#define MAX_FAULTS 16
#define MAX_NODES 8
#define MAX_FAULT_DEPS 4
#define MAP_SIZE 32
#define FILENAME_MAX_SIZE 64
#define MAX_JUMPS 			16
#define MAX_FILE_OFFSET		(FILENAME_MAX_SIZE>>1)
#define SUB_STR_MAX			512

struct tc_key{
    int index;
    int network_direction;
    int fault_nr;
};

struct faultstate_simple{
    //Holds the values for the conditions
    int fault_type_conditions[STATE_PROPERTIES_COUNT+MAX_FUNCTIONS];
    //Holds if the conditions are met
    int conditions_match[STATE_PROPERTIES_COUNT+MAX_FUNCTIONS];
    int dependency_fault_nrs[MAX_FAULT_DEPS];
    int dependency_satisfied[MAX_FAULT_DEPS];
};

struct simplified_fault{
    int fault_type;
    __u64 duration;
    int done;
    __u64 start_time;
    struct faultstate_simple initial;
    struct faultstate_simple end;
    int pid;
    int target;
    int target_if_index;
    int repeat;
    int occurrences;
    int return_value;
    int faults_injected_counter;
    int relevant_conditions;
    int fault_nr;
    int run;
    int quorum_size;
    int faults_done;
    __u64 timestamp;
};

struct fault_key{
    int pid;
    int fault_type;
};

struct fault_description{
    int on;
    int occurences;
    int counter;
    int return_value;
    int syscall_nr;
    int fault_nr;
};

struct info_key{
    int pid;
    //type of state_condition
    int infotype;
};

struct info_state{
    int relevant_states[256];
    int current_value;
    int repeat;
};


struct  relevant_fds{
    __u64 fds[MAX_RELEVANT_FILES];
    int size;
};

struct file_info_simple {
	int size;
	char filename[32];
}__attribute__((packed));

typedef struct file_fd_key_t {
	uint32_t dev;
    uint32_t ino;
} __attribute__((packed)) FileFDKey;

typedef struct file_info_t {
	uint32_t offset;
	uint32_t size;
	char filename[FILENAME_MAX_SIZE];
} FileInfo;

enum fault_type{
    FORK = 1,
    WRITE = 2,
    WRITE_FILE = 8,
    READ = 3,
    READ_FILE = 9,
    NETWORK_ISOLATION = 4,
    BLOCK_IPS = 5,
    DROP_PACKETS = 6,
    CLONE = 7,
    PROCESS_KILL = 11,
    WRITE_RET = 12,
    READ_RET = 13,
    PROCESS_STOP = 14,
    OPEN = 15,
    OPEN_FILE = 20,
    MKDIR = 16,
    MKDIR_FILE = 23,
    NEWFSTATAT_FAULT = 17,
    NEWFSTATAT_FILE_FAULT = 24,
    OPENAT_FAULT = 257,
    OPENAT_RET = 21,
    OPENAT_FILE = 25,
    NEWFSTATAT_RET = 19,
    PROCESS_RESTART = 22,
    FDATASYNC_FAULT = 25,
    FDATASYNCFILE_FAULT = 26,
    FDATASYNC_RET_FAULT = 27,
    FSYNC_FAULT = 74,
    FSYNC_FILE = 740,
    PWRITE64_FAULT = 18,
    ACCEPT_FAULT = 43,
    CLOSE_FAULT = 3,
    FUTEX_FAULT = 202,
    CONNECT_FAULT = 42,
    STAT_FAULT = 49,
    LSEEK_FAULT = 50,
    UNLINK_FAULT = 51,
    SYNC_FILE_RANGE_FAULT = 52,
    BIND_FAULT = 53,
    //LAZYFS
    CLEAR_CACHE = 44,
    CRASH_FS = 45,
    TORN_OP = 46,
    TORN_SEQ = 47,
    TEMP_EMPTY = 999
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
    WRITE_FILE_STATE = 8,
    READ_FILE_STATE = 9,
    CALLCOUNT = 10,
    THREADS_CREATED = 11,
    OPENS = 12,
    DIRCREATED =123,
    NEWFSTATAT_STATE = 14,
    OPENNAT_STATE = 15,
    NEWFSTATAT_FILE_STATE = 16,
    OPENAT_SPECIFIC = 17,
    TIME_STATE = 18,
    FDATASYNC_STATE = 19,
    FDATASYNC_FILE_STATE = 20,
    FSYNC_STATE = 21,
    FSYNCFILE_STATE= 22,
    PWRITE64_STATE = 23,
    ACCEPT_STATE = 24,
    CLOSE_STATE = 25,
    FUTEX_STATE = 26,
    CONNECT_STATE = 27,
    STAT_STATE = 28,
    LSEEK_STATE = 29,
    UNLINK_STATE = 30,
    SYNC_FILE_RANGE_STATE = 31,
    BIND_STATE = 32
};


enum generic{
    ANY_PID = 411,
    LEADER_CHANGE = 13
};

enum condition_mode {
    NORMAL   = 0,
    FAULT_DEP = 1,
    TIME_DEP  = 2,
};

struct event {
	int type;
	int pid;
	int ppid;
    int fault_nr;
	unsigned exit_code;
	unsigned long long duration_ns;
    __u64 state_condition;
    int syscall_nr;
};

struct sys_info {
	int fd;
	int general_syscall_code;
	int file_specific_code;
	int general_fault_code;
	int file_specific_fault_code;
	int fault_count;
	int mode;
};

#endif /* __BPF_SHARED_H_ */
