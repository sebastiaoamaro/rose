#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "aux.skel.h"
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include "fault_schedule.h"
#include "aux.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <dirent.h>
#include <limits.h>
#include <sys/wait.h>


static struct env {
	bool verbose;
	long min_duration_ms;
} env;

//Handles output of created processes

struct aux_bpf* start_aux_maps(){

    struct aux_bpf *skel;
    int err;

    skel = aux_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return NULL;
	}

	/* Load & verify BPF programs */
	err = aux_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return NULL;

	}

	/* Attach tracepoints */
	err = aux_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return NULL;
	}


	err = bpf_map__unpin(skel->maps.rb, "/sys/fs/bpf/rb");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.rb, "/sys/fs/bpf/rb");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
	}

    err = bpf_map__unpin(skel->maps.faults_specification, "/sys/fs/bpf/faults_specification");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.faults_specification, "/sys/fs/bpf/faults_specification");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}

	err = bpf_map__unpin(skel->maps.relevant_state_info, "/sys/fs/bpf/relevant_state_info");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;

	}

	err = bpf_map__pin(skel->maps.relevant_state_info, "/sys/fs/bpf/relevant_state_info");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;

	}

	err = bpf_map__unpin(skel->maps.blocked_ips, "/sys/fs/bpf/blocked_ips");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.blocked_ips, "/sys/fs/bpf/blocked_ips");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}

	err = bpf_map__unpin(skel->maps.files, "/sys/fs/bpf/files");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.files, "/sys/fs/bpf/files");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}


	err = bpf_map__unpin(skel->maps.relevant_fd, "/sys/fs/bpf/relevant_fd");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.relevant_fd, "/sys/fs/bpf/relevant_fd");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}

	err = bpf_map__unpin(skel->maps.faults, "/sys/fs/bpf/faults");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.faults, "/sys/fs/bpf/faults");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}

	err = bpf_map__unpin(skel->maps.auxiliary_info, "/sys/fs/bpf/auxiliary_info");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.auxiliary_info, "/sys/fs/bpf/auxiliary_info");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}

	err = bpf_map__unpin(skel->maps.nodes_status, "/sys/fs/bpf/nodes_status");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.nodes_status, "/sys/fs/bpf/nodes_status");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}

	err = bpf_map__unpin(skel->maps.nodes_pid_translator, "/sys/fs/bpf/nodes_pid_translator");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.nodes_pid_translator, "/sys/fs/bpf/nodes_pid_translator");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}

	err = bpf_map__unpin(skel->maps.pids, "/sys/fs/bpf/pids");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.pids, "/sys/fs/bpf/pids");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}
    return skel;

}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

void bump_file_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= 1048576,
		.rlim_max	= 1048576,
	};

	if (setrlimit(RLIMIT_NOFILE, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_FILELOCK limit!\n");
		exit(1);
	}
}


int get_interface_index(char* if_name){
	struct ifreq ifr;

	size_t if_name_len=strlen(if_name);
	if (if_name_len<sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name,if_name,if_name_len);
		ifr.ifr_name[if_name_len]=0;
	} else {
		printf("interface name is too long \n");
	}

	int fd=socket(AF_UNIX,SOCK_DGRAM,0);
	if (fd==-1) {
		printf("%s \n",strerror(errno));
	}

	if (ioctl(fd,SIOCGIFINDEX,&ifr)==-1) {
    	printf("%s \n",strerror(errno));
	}

	return ifr.ifr_ifindex;
}

int bpf_map_lookup_or_try_init_user(int map, const void *key, void *init,void *value)
{
	long err;
	int err_lookup;

	err_lookup = bpf_map_lookup_elem(map, key, value);
	if (!err_lookup){
		printf("It exists already in lookup and err is %d \n",err_lookup);
		return 1;
	}
	else{
		err = bpf_map_update_elem(map, key, init,BPF_ANY);
		//printf("Created and err is %d \n",err);
		if (err && err != -EEXIST)
			printf("Error in init \n");
		return 0;
	}
}
void pause_process(void* args){
	int pid = ((struct process_fault_args*)args)->pid;
	int duration = ((struct process_fault_args*)args)->duration;
	char *name = ((struct process_fault_args*)args)->name;
	printf("Sleeping for %d before sending SIGCONT\n",duration);
	sleep_for_ms(duration);
	send_signal(pid,SIGCONT,name);
}


int send_signal(int pid, int signal,char* node_name){
	kill(pid,signal);
}


#define DOCKER_SOCKET_PATH "/var/run/docker.sock"
#define CONTAINER_INFO_PATH "/containers/%s/json"

pid_t get_docker_container_pid(const char *container_name) {
    FILE *fp;
    char command[256];
    char output[1024];

    // Construct the Docker command to inspect the container and fetch the PID
    sprintf(command, "sudo docker inspect --format='{{.State.Pid}}' %s", container_name);

    // Open a pipe to read the output of the command
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command\n");
        return -1;
    }

    // Read the output of the command
    if (fgets(output, sizeof(output), fp) == NULL) {
        fprintf(stderr, "Failed to read output\n");
        pclose(fp);
        return -1;
    }

    // Close the pipe
    pclose(fp);

    // Convert the output to PID
    pid_t pid = atoi(output);

    return pid;
}

// Returns a malloc'd, newline-stripped full container ID, or NULL on failure.
// Caller must free().
char *get_docker_container_id(const char *container_name) {
    char command[256];
    snprintf(command, sizeof(command), "sudo docker inspect --format='{{.Id}}' %s", container_name);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        return NULL;
    }
    char output[128];
    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return NULL;
    }
    pclose(fp);
    output[strcspn(output, "\n")] = '\0';
    if (output[0] == '\0') {
        return NULL;
    }
    return strdup(output);
}

// Reads /proc/<container_pid>/cgroup ("0::/some/path" for the cgroup v2
// unified hierarchy) and returns the absolute host path to that cgroup's
// directory under /sys/fs/cgroup, malloc'd (caller frees). NULL on failure.
// Deliberately derived from the container's own real host cgroup rather than
// assuming any particular slice/scope naming.
char *get_container_cgroup_dir(pid_t container_pid) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", container_pid);
    FILE *f = fopen(proc_path, "r");
    if (!f) return NULL;
    char line[512];
    char *result = NULL;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3) == 0) {
            char *rel = line + 3;
            rel[strcspn(rel, "\n")] = '\0';
            char full[600];
            snprintf(full, sizeof(full), "/sys/fs/cgroup%s", rel);
            result = strdup(full);
            break;
        }
    }
    fclose(f);
    return result;
}

// Migrates the calling process into the given container's own cgroup, right
// before execvp() replaces it - tidb-server/pd-server FATAL-crash reading
// their own cgroup's memory.max at Go package-init time; nsenter --mount
// alone does not change cgroup membership (confirmed: without this,
// tidb-server's crash message shows the EXECUTOR's own host session-scope
// cgroup path, not the container's - only `docker exec` migrates
// automatically). Polls briefly for cgroup.procs to become writable (the
// container's cgroup directory can lag container start by a few ms under
// load). See build_nsenter_args()'s comment for why this must be paired with
// nsenter --cgroup to actually work.
void migrate_self_into_container_cgroup(pid_t container_pid) {
    if (container_pid <= 0) return;
    char *dir = get_container_cgroup_dir(container_pid);
    if (!dir) return;
    char procs_path[700];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", dir);

    int fd = -1;
    for (int i = 0; i < 50; i++) {  // 50 * 100ms = 5s
        fd = open(procs_path, O_WRONLY);
        if (fd >= 0) break;
        usleep(100000);
    }
    if (fd < 0) {
        free(dir);
        return;
    }

    char pidbuf[16];
    int len = snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
    write(fd, pidbuf, len);
    close(fd);
    free(dir);
}


pid_t get_lxc_container_pid(const char *container_name) {
    FILE *fp;
    char command[256];
    char output[1024];

    sprintf(command, "lxc list name=%s status=running --format csv -c p", container_name);

    // Open a pipe to read the output of the command
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command\n");
        return -1;
    }

    // Read the output of the command
    if (fgets(output, sizeof(output), fp) == NULL) {
        fprintf(stderr, "Failed to read output\n");
        pclose(fp);
        return -1;
    }

    // Close the pipe
    pclose(fp);

    // Convert the output to PID
    pid_t pid = atoi(output);

    return pid;
}

char* get_docker_container_location(const char* container_name) {
    char command[MAX_COMMAND_LEN];
    char response[MAX_RESPONSE_LEN];

    printf("Finding location for %s \n",container_name);
    // Execute docker container inspect command
    snprintf(command, MAX_COMMAND_LEN, "sudo docker container inspect %s | jq -r '.[0].GraphDriver.Data.MergedDir'", container_name);
    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to execute command");
        exit(EXIT_FAILURE);
    }

    // Read the response from the command
    if (fgets(response, MAX_RESPONSE_LEN, fp) == NULL) {
        perror("Failed to read command output");
        exit(EXIT_FAILURE);
    }

    pclose(fp);

    // Remove trailing newline character
    response[strcspn(response, "\n")] = '\0';

    // Allocate memory for the overlay2 location
    char* overlay2_location = strdup(response);
    if (overlay2_location == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    return overlay2_location;
}

char* get_lxc_container_location(const char* container_name) {
    char command[MAX_COMMAND_LEN];
    char response[MAX_RESPONSE_LEN];

	// Base path
	const char* base_path = "/var/snap/lxd/common/lxd/storage-pools/default/containers";

	// Allocate a buffer large enough to hold the resulting path
	static char container_path[1024]; // Adjust size if needed

	// Format the container path
	snprintf(container_path, sizeof(container_path), "%s/%s/rootfs", base_path, container_name);

	return container_path;
}


void print_block(char* sentence){
	printf("\n============================================================\n");
	printf("  %s\n", sentence);
	printf("============================================================\n\n");
}

void sleep_for_ms(long milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;  // Convert milliseconds to seconds
    ts.tv_nsec = (milliseconds % 1000) * 1000000;  // Convert remaining milliseconds to nanoseconds

    nanosleep(&ts, NULL);
}

long get_children_pids(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror("fopen");
        return 0;
    }

	pid_t child_pid = 0;
    char line[256];
	// Read the line containing child PIDs
    if (fgets(line, sizeof(line), file) != NULL) {
        char *token = strtok(line, " \n");
        if (token != NULL) {
            // Convert the first token to a PID
            char *endptr;
            errno = 0;
            long pid = strtol(token, &endptr, 10);
            if (errno != 0 || *endptr != '\0') {
                perror("strtol");
            } else if (pid >= 0) {
                child_pid = (pid_t)pid;
            }
        }
    }

    fclose(file);
	return child_pid;
}

// Parse state and ppid from /proc/<pid>/stat. comm (field 2) may contain
// spaces/parens, so parse from after the LAST ')'. Returns 0 on success.
static int read_proc_state_ppid(pid_t pid, char *state, pid_t *ppid) {
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char *ok = fgets(buf, sizeof(buf), fp);
    fclose(fp);
    if (!ok) return -1;
    char *p = strrchr(buf, ')');
    if (!p) return -1;
    return sscanf(p + 1, " %c %d", state, ppid) == 2 ? 0 : -1;
}

// Calls fn(pid) for every direct child of parent_pid (skips zombies if live_only).
static int for_each_child(pid_t parent_pid, int sig, int live_only) {
    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        perror("opendir");
        return 0;
    }
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        pid_t pid = atoi(entry->d_name);
        if (pid <= 0) continue;
        char state; pid_t ppid;
        if (read_proc_state_ppid(pid, &state, &ppid) != 0 || ppid != parent_pid) continue;
        if (live_only && state == 'Z') continue;
        if (sig) kill(pid, sig);
        count++;
    }
    closedir(dir);
    return count;
}

// Send `sig` to every direct child of parent_pid.
void signal_child_processes(pid_t parent_pid, int sig) {
    for_each_child(parent_pid, sig, 0);
}

// Number of direct children of parent_pid that are not zombies (not reaped).
int count_live_children(pid_t parent_pid) {
    return for_each_child(parent_pid, 0, 1);
}

void kill_child_processes(pid_t parent_pid) {
    signal_child_processes(parent_pid, SIGKILL);
}

pid_t find_host_pid_for_container_pid(pid_t target_pid) {
    DIR *proc_dir = NULL;
    struct dirent *entry;
    char path[PATH_MAX];
    char line[256];
    FILE *status_file = NULL;
    pid_t host_pid = -1;

    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Failed to open /proc");
        return -1;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        char *endptr;
        pid_t current_pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0')  // skip non-numeric directories
            continue;

        snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);

        status_file = fopen(path, "r");
        if (!status_file) {
            // Process may have exited between readdir() and fopen()
            continue;
        }

        while (fgets(line, sizeof(line), status_file)) {
            if (strncmp(line, "NStgid:", 7) == 0) {
                // Skip leading label
                char *p = line + 7;

                // Skip leading whitespace
                while (*p == ' ' || *p == '\t') p++;

                // Parse all PIDs in namespace hierarchy
                pid_t ns_pid;
                char *token = strtok(p, "\t ");
                int idx = 0;

                while (token) {
                    ns_pid = (pid_t) atoi(token);
                    if (ns_pid == target_pid) {
                        host_pid = current_pid;
                        goto cleanup; // break out safely
                    }
                    token = strtok(NULL, "\t ");
                    idx++;
                }
                break;
            }
        }

        if (fclose(status_file) != 0 && errno != ENOENT) {
            // Only log unexpected close errors
            perror("fclose");
        }
        status_file = NULL;
    }

cleanup:
    if (status_file) {
        if (fclose(status_file) != 0 && errno != ENOENT)
            perror("fclose");
    }
    if (proc_dir)
        closedir(proc_dir);

    return host_pid;
}

char **build_nsenter_args(const char *pid_str,int container_type) {
    size_t size = 16;
    char **nsenter_args = malloc(size * sizeof(char *));
    if (nsenter_args == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    if (container_type == CONTAINER_TYPE_DOCKER) {
        // NOTE on cgroups: a bare `nsenter --mount` (without --cgroup) does
        // NOT change cgroup membership - `docker exec` does that
        // automatically, this doesn't. A prior fix attempt migrated the
        // process's real cgroup membership (write PID into the container's
        // cgroup.procs - see migrate_self_into_container_cgroup() in this
        // file, called from custom_popen_cgroup() before execvp) but left
        // nsenter as --mount-only, reasoning `--cgroup` "didn't help" in an
        // earlier test. That earlier test never combined it with a working
        // migration, so it never actually diagnosed the real problem: after
        // `--mount` alone, /sys/fs/cgroup inside the new mount namespace is
        // ALREADY cgroup-namespace-virtualized to the container's own cgroup
        // as "/" (baked into the mount at container-creation time) - but
        // /proc/self/cgroup for a process that only joined the MOUNT
        // namespace still reports the real, host-absolute path (e.g.
        // "/docker/<id>"). Go's (and other runtimes') cgroup-v2 self-
        // detection naively concatenates /sys/fs/cgroup + that reported path
        // + "/memory.max" - producing a doubled, non-existent path
        // regardless of how correct the underlying migration is. Confirmed
        // directly: `nsenter --mount` only, migrated correctly, still
        // produces ENOENT on the exact doubled path; adding `--cgroup` SO
        // THE PROCESS ALSO JOINS THE CGROUP NAMESPACE (after migrating, so
        // real membership already matches that namespace) makes
        // /proc/self/cgroup correctly report "/", matching what the
        // already-virtualized mount expects - confirmed working manually
        // (cat /sys/fs/cgroup/memory.max succeeds) and via a real
        // run_schedule.sh TiDB run. Migration must still happen (see
        // custom_popen_cgroup) - `--cgroup` alone, without migration, only
        // joins the namespace and shows a namespace-relative "../.."
        // escape path (real membership still outside), which is what the
        // earlier, unmigrated test actually saw.
        nsenter_args[0] = "nsenter";
        nsenter_args[1] = "--target";
        nsenter_args[2] = (char *)pid_str;
        nsenter_args[3] = "--mount";
        nsenter_args[4] = "--uts";
        nsenter_args[5] = "--ipc";
        nsenter_args[6] = "--net";
        nsenter_args[7] = "--pid";
        nsenter_args[8] = "--cgroup";
        nsenter_args[9] = "--";
        nsenter_args[10] = NULL;
    }
    if (container_type == CONTAINER_TYPE_LXC) {
        nsenter_args[0] = "nsenter";
        nsenter_args[1] = "--target";
        nsenter_args[2] = (char *)pid_str;
        nsenter_args[3] = "--user";
        nsenter_args[4] = "--mount";
        nsenter_args[5] = "--ipc ";
        nsenter_args[6] = "--net";
        nsenter_args[7] = "--pid";
        nsenter_args[8] = "--uts";
        nsenter_args[9] = "--";
        nsenter_args[10] = NULL;
    }

    return nsenter_args;
}

long long get_nanoseconds() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

///////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////PROCESS_SPAWNING/////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

static int ready = 0;
static void sig_handler(int signum){
    ready = 1;
}

static FILE * custom_popen_impl(char* command, char **args, char **env,char type, pid_t* pid, int container_process, pid_t cgroup_container_pid)
{
    pid_t child_pid;
    int fd[2];
    pipe(fd);
    if((child_pid = fork()) == -1)
    {
        perror("fork \n");
        exit(1);
    }
    if (child_pid == 0)
    {
        if (type == 'r')
        {
            close(fd[0]);
            dup2(fd[1], 1);
        }
        else
        {
            close(fd[1]);
            dup2(fd[0],0);
        }

        setpgid(child_pid, child_pid); //Needed so negative PIDs can kill children of /bin/sh

        //If it is not a container process, wait for the signal to start
        if (!container_process){
            signal(SIGUSR1,sig_handler);
            while(true){
                if(ready){
                    break;
                }
                sleep_for_ms(10);
            }
        }
        if (cgroup_container_pid > 0) {
            migrate_self_into_container_cgroup(cgroup_container_pid);
        }
        // execvp inherits this process's environment, so node `env:` entries
        // (KEY=VALUE) must be put into it here - they were parsed and passed
        // down but never applied.
        for (int i = 0; env != NULL && env[i] != NULL; i++){
            putenv(env[i]);
        }
        int err = execvp(command,args);
        if (err < 0)
            printf("COMMAND:%s, Err in execvp: %s (errno=%d)\n", command, strerror(errno), errno);
        exit(0);
    }
    else
    {
        if (type == 'r')
        {
            close(fd[1]); //Close the WRITE end of the pipe since parent's fd is read-only
        }
        else
        {
            close(fd[0]); //Close the READ end of the pipe since parent's fd is write-only
        }

    }
    *pid = child_pid;
    if (type == 'r')
    {
        return fdopen(fd[0], "r");
    }

    return fdopen(fd[1], "w");
}

FILE * custom_popen(char* command, char **args, char **env,char type, pid_t* pid, int container_process)
{
    return custom_popen_impl(command, args, env, type, pid, container_process, 0);
}

FILE * custom_popen_cgroup(char* command, char **args, char **env,char type, pid_t* pid, int container_process, pid_t cgroup_container_pid)
{
    return custom_popen_impl(command, args, env, type, pid, container_process, cgroup_container_pid);
}
