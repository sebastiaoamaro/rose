#ifndef __AUX_H_
#define __AUX_H_
#include "bpf_shared.h"
#define PATH_MAX	4096
#define FILENAME_SIZE 64
#define MAX_FILE_LOCATION_LEN 1024
#define MAX_COMMAND_LEN 512
#define MAX_RESPONSE_LEN 1024
#define CONTAINER_TYPE_DOCKER 1
#define CONTAINER_TYPE_LXC 2
#define CONTAINER_TYPE_DOCKER_AUTOMATIC 3

struct process_fault_args{
	int pid;
	int duration;
    int node_to_restart;
    char* name;
};

struct aux_bpf* start_aux_maps();
int get_interface_index(char*);
int bpf_map_lookup_or_try_init_user(int, const void *, void *,void *);
void pause_process(void* args);
void print_block(char*);
pid_t get_lxc_container_pid(const char *container_name);
pid_t get_docker_container_pid(const char *container_name);
char *get_docker_container_id(const char *container_name);
char *get_container_cgroup_dir(pid_t container_pid);
void migrate_self_into_container_cgroup(pid_t container_pid);
char* get_lxc_container_location(const char* container_name);
char* get_docker_container_location(const char* container_name);
void sleep_for_ms(long milliseconds);
int send_signal(int pid, int signal,char*);
long get_children_pids(pid_t pid);
void kill_child_processes(pid_t parent_pid);
void signal_child_processes(pid_t parent_pid, int sig);
int count_live_children(pid_t parent_pid);
void bump_memlock_rlimit(void);
void bump_file_rlimit(void);
pid_t find_host_pid_for_container_pid(pid_t target_pid);
char **build_nsenter_args(const char *pid_str,int container_type);
long long get_nanoseconds();
void print_output(void* args);
FILE * custom_popen(char* command,char** args,char** env, char type, pid_t* pid,int container_process);
FILE * custom_popen_cgroup(char* command,char** args,char** env, char type, pid_t* pid,int container_process, pid_t cgroup_container_pid);
#endif /* __AUX_H */
