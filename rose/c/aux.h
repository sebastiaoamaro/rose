#ifndef __AUX_H_
#define __AUX_H_
#define STRING_SIZE 128
#define MAX_ENTRIES 10240
#define PATH_MAX	4096
#define STATE_PROPERTIES_COUNT 34
#define MAX_IPS_BLOCKED 16
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128
#define FUNCNAME_MAX 512
#define MAX_FUNCTIONS 16
#define FILENAME_MAX_SIZE 64
#define FAULTSSUPPORTED 26
#define MAX_RELEVANT_FILES 256
#define MAX_ARGS 16
#define MAX_FAULTS 32
#define MAP_SIZE 32

#define MAX_FILE_LOCATION_LEN 1024
#define MAX_COMMAND_LEN 512
#define MAX_RESPONSE_LEN 1024

struct fault;

struct tc_key{
    int index;
    int network_direction;
};

struct faultstate_simple{
    int fault_type_conditions[STATE_PROPERTIES_COUNT+MAX_FUNCTIONS];
    int conditions_match[STATE_PROPERTIES_COUNT+MAX_FUNCTIONS];
};

struct simplified_fault{
    int faulttype;
    __u64 duration;
    int done;
    __u64 start_time;
    struct faultstate_simple initial;
    struct faultstate_simple end;
    int pid;
    int target;
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
    int faulttype;
};

struct fault_description{
    int on;
    int occurences;
    int counter;
    int return_value;
    int syscall_nr;
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
    FSYNC = 74,
    FSYNC_FILE = 740,
    PWRITE64_FAULT = 18,
    ACCEPT_FAULT = 43,
    CLOSE_FAULT = 3,
    FUTEX_FAULT = 202,
    CONNECT_FAULT = 42,
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
    WRITE_FILE_STATE = 22,
    READ_FILE_STATE = 23,
    CALLCOUNT = 10,
    THREADS_CREATED = 11,
    OPENS = 13,
    DIRCREATED =14,
    NEWFSTATAT_STATE = 15,
    OPENNAT_COUNT = 16,
    // VFS_FSTATAT_COUNT = 17,
    // VFS_FSTATAT_SPECIFIC = 18,
    NEWFSTATAT_FILE_STATE = 19,
    OPENAT_SPECIFIC = 20,
    TIME_FAULT = 21,
    FDATASYNC_STATE = 24,
    FDATASYNCFILE_STATE = 25,
    FSYNC_STATE = 27,
    FSYNCFILE_STATE= 28,
    PWRITE64_STATE = 29,
    ACCEPT_STATE = 30,
    CLOSE_STATE = 31,
    FUTEX_STATE = 32,
    CONNECT_STATE = 33
};


enum generic{
    ANY_PID = 411,
    LEADER_CHANGE = 13
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


struct process_fault_args{
	int pid;
	int duration;
    int node_to_restart;
    char* name;
};


struct aux_bpf* start_aux_maps();
int get_interface_index(char*);
void build_fault(struct fault* ,int,int,int,int,int,int,char**,int,char *);
void set_if_name(struct fault*,char *);
void add_function_to_monitor(struct fault*,char*,int);
int bpf_map_lookup_or_try_init_user(int, const void *, void *,void *);
int get_interface_names(char **,int);
int translate_pid(int);
void pause_process(void* args);
void print_block(char*);
pid_t get_container_pid(const char *container_name);
char* get_overlay2_location(const char* container_name);
void kill_process(void* args);
void sleep_for_ms(long milliseconds);
bool is_element_in_array(int arr[], int size, int element);
void print_fault_schedule();
int send_signal(int pid, int signal,char*);
long get_children_pids(pid_t pid);
void kill_child_processes(pid_t parent_pid);
#endif /* __AUX_H */
