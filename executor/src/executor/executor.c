// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <bits/pthreadtypes.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <libgen.h>
#include <limits.h>
//Modules
#include <aux.skel.h>
#include <fault_inject.h>
#include <fault_inject.skel.h>
#include <uprobes.h>
#include <uprobes.skel.h>
#include <fault_schedule.h>
#include <aux.h>
#include <sys/wait.h>
#include <stdarg.h>

// Only meant to catch a genuinely hung setup script (e.g. a wedged compile or
// `docker compose up`) - generous on purpose, never expected to fire on a
// realistic compile or image pull. Deliberately separate from
// plan->setup.duration, which is an unrelated post-completion warm-up sleep.
#define SETUP_SCRIPT_TIMEOUT_SEC 300

void process_counter(const struct event *event,int stateinfo);
int process_tc(const struct event*);
void process_fs(const struct event*);
void inject_fault(int fault_type,int pid,int fault_id,int syscall_nr);
void setup_begin_conditions();
void setup_node_scripts();
void start_container_nodes_scripts();
void start_nodes_scripts();
void collect_container_processes();
FILE* start_target_process(int node_number,int *pid);
FILE* start_target_process_in_container(int node_number,int *pid);
void insert_relevant_condition_in_ebpf(int fault_nr,int pid,int cond_nr,int call_count);
void count_time();
void get_fd_of_maps (struct aux_bpf *bpf);
static int handle_event(void *ctx,void *data,long unsigned int data_sz);
void run_setup();
void collect_container_pids();
void apply_node_latency();
void print_output(void* args);
void start_workload();
void restart_process(void* args);
void add_faults_to_bpf();
void choose_leader();
int setup_tc_progs();
void retrieve_new_pid_container(int node_nr,int nsenter_pid);
void update_node_pid_ebpf(int node_nr,int new_pid,int boot_pid, int current_pid_pre_restart);
int get_node_nr_from_pid(int pid);
void reinject_uprobes(int node_nr);
void send_info_to_tracer();
void send_node_and_pid_to_tracer(int container_pid,int container_type, int pid, char* node_name,int if_index);
void create_pipes();
void start_tracer();
void open_tracer_pipe();
void write_start_event();
void handle_lazyfs_events();
void start_lazyfs_handler(void* args);
void setup_uprobes();
void start_lazyfs();
void start_pre_workload();
static void abort_run(const char *stage, const char *fmt, ...);
static void terminate_children(void);

const char *argp_program_version = "Tool for FI 0.01";
const char *argp_program_bug_address = "sebastiao.amaro@ŧecnico.ulisboa.pt";
const char argp_program_doc[] = "eBPF Fault Injection Tool.\n"
				"\n"
				"USAGE: ./executor/executor [-f fault count] [-d network device count] [-p process ids] \n";


//TODO: remove non_used rename to maps
static struct constants {
	int fault_type_fd;
	int relevant_state_info_fd;
	int blocked_ips;
	int relevant_fd;
	int bpf_map_fault_fd;
	int files;
	int pid;
	char *inputfilename;
	int uprobemode;
	int tracingmode;
	int faultsverbose;
	int target_pid;
	int maintainpid;
	int time_map_fd;
	int mode;
	int auxiliary_info_map_fd;
	int nodes_status_map_fd;
	int nodes_translator_map_fd;
	int pids;
	char *collect_process_info_pipe;

} constants;

struct process_args {
	int *pid;
	FILE* fp;
};

//Main structs for reproduction
static fault* faults;
static node* nodes;
static execution_plan* plan;
static tracer* deployment_tracer;

static int FAULT_COUNT = 0;
static int NODE_COUNT = 0;
static int QUORUM = 0;
static int LEADER_PID = 0;
int *majority;

static pthread_t tracer_output;

//Handle exits
static volatile bool exiting = false;
static void sig_handler(int sig){exiting = true;}

int main()
{
	// stdout is fully block-buffered (not line-buffered) whenever it's
	// redirected to a file instead of a tty - which is how this binary
	// always runs in practice (sunflower.py/run_schedule.sh redirect it
	// to a log file). Without this, printf() output - including every
	// cleanup-path message below (STARTING CLEANUP, KILLING NODES,
	// WAITING FOR TRACER, etc) - sits in an in-process buffer and is
	// silently lost if the process is ever killed before it exits
	// normally (SIGKILL, or a crash), making the log file lie about
	// whether cleanup code actually ran. Force line buffering so the
	// log always reflects real-time execution.
	setvbuf(stdout, NULL, _IOLBF, 0);

    print_block("ROSE STARTED");
	bump_memlock_rlimit();
	bump_file_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct aux_bpf *aux_bpf = start_aux_maps();
	if(!aux_bpf){
		printf("Error in creating aux_bpf_maps\n");
		return 0;
	}

	get_fd_of_maps(aux_bpf);

	//Start tracer
	deployment_tracer = build_tracer();
	if (deployment_tracer){
		create_pipes();
		print_block("Started tracer");
		start_tracer();
		open_tracer_pipe();
	}

	//Build structs in fault_schedule.c
	plan = build_execution_plan();
	run_setup();
	nodes = build_nodes();
	faults = build_faults_extra();
	NODE_COUNT = get_node_count();
	QUORUM = (NODE_COUNT/2)+1;
	FAULT_COUNT = get_fault_count();
	majority = (int *)malloc(QUORUM*sizeof(int));

	print_block("SETTING UP NODES");
	collect_container_pids();
	apply_node_latency();
	setup_node_scripts();
	collect_container_processes();

	//We need the executor to run first then the trace, for some reason the order of running uprobes is reversed.
	setup_uprobes();

	if (deployment_tracer){
	    send_info_to_tracer();
	}

	setup_tc_progs();

	int err;
	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(aux_bpf->maps.rb), handle_event, NULL, NULL);


	start_lazyfs();
	//If they are containers we start before the workload
	write_start_event();
	start_container_nodes_scripts();

	//Start eBPF FI program
	choose_leader();
	setup_begin_conditions();
	add_faults_to_bpf();

	struct fault_inject_bpf* fault_inject_bpf;

	fault_inject_bpf = fault_inject(FAULT_COUNT,constants.mode);

	if (!fault_inject_bpf){
		printf("Error in creating fault injection bpf\n");
		goto cleanup;
	}

	start_pre_workload();

	//These are nodes which are not containers thus we know their pid beforehand and we can start them after the setup, catching all events
	start_nodes_scripts();

	pthread_t thread_id;
	pthread_create(&thread_id, NULL, (void *)count_time, NULL);
	if(plan->workload.wait_time > 0 ){
		printf("SLEEPING: %d, BEFORE WORKLOAD\n",plan->workload.wait_time);
		sleep(plan->workload.wait_time);
	}
	start_workload();

	while (!exiting) {
		err = ring_buffer__poll(rb, 1000 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
	printf("STARTING CLEANUP\n");

	cleanup:

	if (plan->workload.wait_workload > 0){
		printf("WAITING FOR WORKLOAD TO END BEFORE WORKLOAD CLEANUP\n");
		while (waitpid(plan->workload.pid, NULL, WNOHANG) == 0) {
            sleep(1);
		 }
	}

	if(plan){

		if (plan->workload.pid){
		    printf("KILLING WORKLOAD(PID:%d)\n",plan->workload.pid);
			kill(plan->workload.pid,SIGTERM);
			// Wait for it to exit
            int status;
            if (waitpid(plan->workload.pid, &status, 0) == -1) {
                perror("waitpid failed");
            } else {
                printf("Workload terminated with status %d\n", status);
            }

       	    printf("CLOSING WORKLOAD PIPE\n");
            int result = fclose(plan->workload.read_end);
            if (result < 0){
                printf("Closing read_end pre_workload failed \n");
            }
    		printf("CLOSED WORKLOAD PIPE\n");
		}
	}

	if (plan->pre_workload.pid){
	    printf("CLOSING PRE_WORKLOAD PIPE\n",plan->workload.pid);
		int result = fclose(plan->pre_workload.read_end);
		if (result < 0){
		    printf("Closing read_end pre_workload failed \n");
		}
	}

	// Ask the TC programs (network_manager) to detach BEFORE both the cleanup
	// script (which may destroy the containers/interfaces they are attached to,
	// making the detach fail with ENODEV) and the child sweep (SIGKILL would
	// give them no chance to run their SIGINT handler, leaving filters/progs on
	// any interface that outlives the run).
	{
		pid_t tc_pids[2 * NODE_COUNT];
		int tc_count = 0;
		for(int i =0; i< NODE_COUNT;i++){
			if(nodes[i].pid_tc_in > 0)  tc_pids[tc_count++] = nodes[i].pid_tc_in;
			if(nodes[i].pid_tc_out > 0) tc_pids[tc_count++] = nodes[i].pid_tc_out;
		}
		for(int i = 0; i < tc_count; i++)
			kill(tc_pids[i], SIGINT);
		// network_manager polls its exit flag once per second; allow ~5s.
		for(int waited = 0; waited < 50 && tc_count > 0; waited++){
			int remaining = 0;
			for(int i = 0; i < tc_count; i++){
				if(tc_pids[i] > 0){
					pid_t r = waitpid(tc_pids[i], NULL, WNOHANG);
					if(r == 0) remaining++;
					else tc_pids[i] = 0; // exited, or not our child anymore
				}
			}
			if(!remaining) break;
			usleep(100000);
		}
		for(int i =0; i< NODE_COUNT;i++){
			nodes[i].pid_tc_in = 0;
			nodes[i].pid_tc_out = 0;
		}
	}

	printf("SLEEPING: %d, BEFORE CLEANUP\n",plan->cleanup.duration);
	if(plan->cleanup.duration)
	    sleep(plan->cleanup.duration);
	printf("EXPERIMENT ENDED, RUNNING CLEANUP SCRIPT\n");

	if (plan){
		if(strcmp(plan->cleanup.script,"")){
			printf("RUNNING CLEANUP SCRIPT %s \n",plan->cleanup.script);
			int status = system(plan->cleanup.script);
			if (status == -1) {
					printf("Failed to call script.\n");
				} else {
					printf("CLEANUP SUCESSFULL.\n");
			}
		}
	}


	//Add ROSE faults to tracer and close it
	if(deployment_tracer){
		int key;
		struct simplified_fault value = {};
		int next_key;
		FILE *fptr;

		fptr = fopen("/tmp/history.txt", "a");

		//Add faults to the trace
		printf("ROSE: ADDING FAULTS TO TRACE\n");
		for (int i = 0; i< FAULT_COUNT;i++){
			struct simplified_fault fault;
			int err_lookup;
			err_lookup = bpf_map_lookup_elem(constants.bpf_map_fault_fd, &i,&fault);
			if (err_lookup){
				printf("Did not find elem in count_time errno is %d \n",errno);
			}
			if (fault.timestamp > 0){
				int fault_nr = fault.fault_nr;
				int target = fault.target;
				// `target` only means a nodes[] index for a STATICALLY
				// scheduled fault (schedule_parser/faults.py sets it to
				// node.node_nr, or -1/-2 for primary/majority). A fault
				// armed dynamically via RoseInjector.inject_fault() (the
				// only kind sunflower.py's coverage-fixed mode ever uses)
				// has no access to executor's nodes[] array at all and
				// defaults target to the fault's own real PID instead -
				// confirmed via a core dump: target=17661 (a live pid,
				// not a node index) crashed this exact fprintf's %s on
				// nodes[17661].name, deep out of bounds of the NODE_COUNT
				// (5) nodes[] array, every single run under sunflower.py.
				// Bounds-check before indexing nodes[] and fall back to
				// printing the raw target so a dynamically-injected
				// fault's history line stays informative instead of
				// crashing the whole cleanup path.
				if (fault_nr < 0 || fault_nr >= FAULT_COUNT)
					continue;
				if (target == -2)
					fprintf(fptr,"Node:%s,Pid:0,Tid:0,event_type:Fault,event_name:%s,ret:0,time:%llu,arg1:%d,arg2:0,arg3:0,arg4:0,arg5:na\n","majority",faults[fault_nr].name,fault.timestamp,fault.fault_nr);
				else if (target == -1)
					fprintf(fptr,"Node:%s,Pid:0,Tid:0,event_type:Fault,event_name:%s,ret:0,time:%llu,arg1:%d,arg2:0,arg3:0,arg4:0,arg5:na\n","leader",faults[fault_nr].name,fault.timestamp,fault.fault_nr);
				else if (target >= 0 && target < NODE_COUNT)
					fprintf(fptr,"Node:%s,Pid:0,Tid:0,event_type:Fault,event_name:%s,ret:0,time:%llu,arg1:%d,arg2:0,arg3:0,arg4:0,arg5:na\n",nodes[target].name,faults[fault_nr].name,fault.timestamp,fault.fault_nr);
				else
					fprintf(fptr,"Node:pid_%d,Pid:0,Tid:0,event_type:Fault,event_name:%s,ret:0,time:%llu,arg1:%d,arg2:0,arg3:0,arg4:0,arg5:na\n",target,faults[fault_nr].name,fault.timestamp,fault.fault_nr);
			}
		}
		fclose(fptr);
		char message[] = "finished\n";
		if (write(deployment_tracer->pipe_write_end, message, strlen(message)+1) == -1) {  // +1 to include the null terminator
            perror("write");
            exit(EXIT_FAILURE);
        }

		printf("WAITING FOR TRACER: %d \n",deployment_tracer->pid);
		waitpid(deployment_tracer->pid,NULL,0);
		printf("TRACER FINISHED: %d \n",deployment_tracer->pid);
	}

	if(!fault_inject_bpf)
		fault_inject_bpf__destroy(fault_inject_bpf);
	if(!aux_bpf)
		aux_bpf__destroy(aux_bpf);
	if(!rb)
		ring_buffer__free(rb);

	// Reap whatever direct children are left (node-script wrappers, lazyfs, ...).
	terminate_children();

	printf("KILLING NODES and TC PROGS\n");
	for(int i =0; i< NODE_COUNT;i++){

		if(strlen(nodes[i].script)){
			//kill(nodes[i].current_pid,SIGTERM);
			waitpid(nodes[i].current_pid,NULL,0);
			printf("KILLED PID: %d\n",nodes[i].current_pid);
		}
	}

    if (plan->setup.pid){
       	    printf("KILLING SETUP(PID:%d)\n",plan->setup.pid);
          		kill(plan->setup.pid,SIGTERM);
      		// Wait for it to exit
                    int status;
                    if (waitpid(plan->setup.pid, &status, 0) == -1) {
                        perror("waitpid failed");
                    } else {
                        printf("Setup terminated with status %d\n", status);
                }

                printf("CLOSING SETUP PIPE\n");
                fclose(plan->setup.read_end);
                printf("CLOSED SETUP PIPE\n");
    }

	if(plan->lazyfs.pid > 0){
	    printf("KILLING LAZYFS(PID:%d)\n",plan->lazyfs.pid);
	    kill(plan->lazyfs.pid,SIGTERM);
		//kill_child_processes(plan->lazyfs.pid);
	}
	printf("FINISHED CLEANUP\n");
	return 0;
}

void start_tracer(){
	char *args_script[6];

	args_script[0] = (char*)malloc(STRING_SIZE*sizeof(char));
	strcpy(args_script[0],deployment_tracer->tracer_location);
	args_script[1] = (char*)malloc(STRING_SIZE*sizeof(char));
	strcpy(args_script[1],deployment_tracer->tracing_type);
	args_script[2] = (char*)malloc(STRING_SIZE*sizeof(char));
	strcpy(args_script[2],deployment_tracer->functions_file);
	args_script[3] = (char*)malloc(STRING_SIZE*sizeof(char));
	strcpy(args_script[3],deployment_tracer->binary_path);
	args_script[4] = (char*)malloc(STRING_SIZE*sizeof(char));
	strcpy(args_script[4],deployment_tracer->pipe_location);
	args_script[5]=(char*)malloc(1*sizeof(char));
	args_script[5]= NULL;

	char *env_script[1];
	env_script[0]=(char*)malloc(1*sizeof(char));
	env_script[0]= NULL;

	FILE *fp = custom_popen(deployment_tracer->tracer_location,args_script,env_script,'r',&deployment_tracer->pid,0);

	struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));
	args->fp= fp;
	args->pid = &(deployment_tracer->pid);
	pthread_create(&tracer_output, NULL, (void *)print_output, (void*)args);
	sleep_for_ms(10);
	send_signal(deployment_tracer->pid,SIGUSR1,"tracer");

}

void create_pipes(){
    char write_pipe[FILENAME_SIZE];
    char read_pipe[FILENAME_SIZE];

    if (snprintf(write_pipe, sizeof(write_pipe), "%s_write", deployment_tracer->pipe_location) < 0) {
        perror("snprintf for write_pipe");
        exit(EXIT_FAILURE);
    }
    if (snprintf(read_pipe, sizeof(read_pipe), "%s_read", deployment_tracer->pipe_location) < 0) {
        perror("snprintf for read_pipe");
        exit(EXIT_FAILURE);
    }
    if (mkfifo(write_pipe, 0666) == -1) {
        perror("mkfifo (write pipe)");
        exit(EXIT_FAILURE);
    }
    if (mkfifo(read_pipe, 0666) == -1) {
        perror("mkfifo (read pipe)");
        exit(EXIT_FAILURE);
    }
    printf("  [pipe]  write -> %s\n", write_pipe);
    printf("  [pipe]  read  -> %s\n", read_pipe);
}
void open_tracer_pipe(){
	int fd;
    char write_pipe[FILENAME_SIZE];
    char read_pipe[FILENAME_SIZE];
	// Step 2: Open the FIFO in write-only mode
    if (snprintf(write_pipe, sizeof(write_pipe), "%s_write", deployment_tracer->pipe_location) < 0) {
        perror("snprintf for write_pipe");
        exit(EXIT_FAILURE);
    }
    if (snprintf(read_pipe, sizeof(read_pipe), "%s_read", deployment_tracer->pipe_location) < 0) {
        perror("snprintf for read_pipe");
        exit(EXIT_FAILURE);
    }

	fd = open(write_pipe, O_WRONLY);
	if (fd == -1) {
	    printf("  ✗ failed to open FIFO for write: %s\n", write_pipe);
		perror("open");
		exit(EXIT_FAILURE);
	}
	deployment_tracer->pipe_write_end = fd;

	fd = open(read_pipe, O_RDONLY);
	if (fd == -1) {
	    printf("  ✗ failed to open FIFO for read: %s\n", read_pipe);
		perror("open");
		exit(EXIT_FAILURE);
	}
	deployment_tracer->pipe_read_end = fd;

}

void write_start_event() {
    FILE *fptr;
    fptr = fopen("/tmp/history.txt", "a");
    long long ts = get_nanoseconds();
    fprintf(fptr,"Node:ROSE,Pid:0,Tid:0,event_type:start,event_name:start,ret:0,time:%llu,arg1:0,arg2:0,arg3:0,arg4:0,arg5:na\n",ts);
    fclose(fptr);

}

//Save FD of maps in constants
void get_fd_of_maps (struct aux_bpf *bpf){
	constants.relevant_state_info_fd = bpf_map__fd(bpf->maps.relevant_state_info);
	constants.fault_type_fd = bpf_map__fd(bpf->maps.faults_specification	);
	constants.blocked_ips = bpf_map__fd(bpf->maps.blocked_ips);
	constants.files = bpf_map__fd(bpf->maps.files);
	constants.relevant_fd = bpf_map__fd(bpf->maps.relevant_fd);
	constants.bpf_map_fault_fd = bpf_map__fd(bpf->maps.faults);
	constants.auxiliary_info_map_fd = bpf_map__fd(bpf->maps.auxiliary_info);
	constants.nodes_status_map_fd = bpf_map__fd(bpf->maps.nodes_status);
	constants.nodes_translator_map_fd = bpf_map__fd(bpf->maps.nodes_pid_translator);
	constants.pids = bpf_map__fd(bpf->maps.pids);


};

// Stops every direct child of this executor: SIGTERM, wait up to ~3s for them
// to exit, then SIGKILL stragglers. Scans /proc rather than using stored node
// pids, which are not reliably direct children (container nodes get their pid
// overwritten with the real process's host pid). Callers that own children
// needing a specific signal (the TC network_manager procs want SIGINT so they
// can detach) must stop those first.
static void terminate_children(void) {
	signal_child_processes(getpid(), SIGTERM);
	for(int waited = 0; waited < 30 && count_live_children(getpid()) > 0; waited++)
		usleep(100000);
	if(count_live_children(getpid()) > 0)
		printf("CHILDREN STILL ALIVE AFTER SIGTERM, SENDING SIGKILL\n");
	kill_child_processes(getpid());
}

// Aborts the run with a clear, loud diagnostic instead of silently continuing
// past a setup that never finished or a fault that was never actually armed
// (see the run_setup()/setup_uprobes() call sites below). Both of those run
// before `nodes`/`faults`/`NODE_COUNT`/`fault_inject_bpf`/the ring buffer are
// declared in main(), and are separate functions from main() besides, so
// `goto cleanup;` isn't available here - this is the equivalent loud-failure
// idiom for that earlier phase. Kills whatever children this executor has
// already spawned and best-effort runs the schedule's cleanup script, then
// terminates.
static void abort_run(const char *stage, const char *fmt, ...) {
	va_list args;
	fprintf(stderr, "\n  [%s]  FATAL: ", stage);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n  [%s]  aborting run.\n", stage);

	// Callers run before setup_tc_progs(), so no TC procs exist yet.
	terminate_children();

	if (plan && strlen(plan->cleanup.script)) {
		printf("  [%s]  running cleanup script before exit: %s\n", stage, plan->cleanup.script);
		system(plan->cleanup.script);
	}

	exit(EXIT_FAILURE);
}

void run_setup(){
    print_block("SETTING UP EXPERIENCE");
	if(!plan)
		return;

	char *args_script[1];

	char *env_script[1];

	args_script[0]=(char*)malloc(1*sizeof(char));

	args_script[0]= NULL;

	env_script[0]=(char*)malloc(1*sizeof(char));

	env_script[0]= NULL;


	if(strlen(plan->setup.script)){
		printf("  [setup]  starting setup script\n");
		FILE *fp = custom_popen(plan->setup.script,args_script,env_script,'r',&(plan->setup.pid),0);
		plan->setup.read_end = fp;
		pthread_t thread_id;
		struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

		args->fp= fp;
		args->pid = &(plan->setup.pid);
		//pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	}

	if(strlen(plan->pre_workload.script)){
		printf("  [setup]  starting pre-workload script\n");
		FILE *fp = custom_popen(plan->pre_workload.script,args_script,env_script,'r',&(plan->pre_workload.pid),0);
		plan->pre_workload.read_end = fp;
		pthread_t thread_id;
		struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

		args->fp= fp;
		args->pid = &(plan->pre_workload.pid);
		//pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	}

	if(strlen(plan->workload.script)){
		printf("  [setup]  starting workload script\n");
		FILE *fp = custom_popen(plan->workload.script,args_script,env_script,'r',&(plan->workload.pid),0);
		plan->workload.read_end = fp;
		pthread_t thread_id;
		struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

		args->fp= fp;
		args->pid = &(plan->workload.pid);
		//pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	}

	if(strlen(plan->lazyfs.script)){

		char *lazyfs_args_script[9];

        lazyfs_args_script[0] = plan->lazyfs.script;
        lazyfs_args_script[1] = "-c";
        lazyfs_args_script[2] = "/vagrant/lazyfs/lazyfs/config/default.toml";
        lazyfs_args_script[3] = "-m";
        lazyfs_args_script[4] = plan->lazyfs.mount_dir;
        lazyfs_args_script[5] = "-r";
        lazyfs_args_script[6] = plan->lazyfs.root_dir;
        lazyfs_args_script[7] = "-f";
        lazyfs_args_script[8] = NULL;

    	print_block("Creating LazyFS process");
    	FILE *fp = custom_popen(plan->lazyfs.script,lazyfs_args_script,env_script,'r',&(plan->lazyfs.pid),0);
    	plan->lazyfs.read_end = fp;
    	pthread_t thread_id;
    	struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

    	args->fp= fp;
    	args->pid = &(plan->lazyfs.pid);
    	//pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	}
	//Start setup
	if(strlen(plan->setup.script)){
	    sleep_for_ms(10);
    	kill(plan->setup.pid,SIGUSR1);

    	// Wait for the setup script to actually finish (e.g. the executor-side
    	// `go test -race -c` rebuild in unit-test/violet schedules, or
    	// `docker compose up -d` in live-cluster schedules) instead of just
    	// sleeping and hoping it's done - a broken/incomplete setup used to
    	// proceed silently and show up later only as "0 FAULT", indistinguishable
    	// from the target syscall never being reached.
    	printf("  [setup]  waiting for setup script (pid=%d) to complete...\n", plan->setup.pid);
    	int status;
    	int elapsed = 0;
    	pid_t wp;
    	while ((wp = waitpid(plan->setup.pid, &status, WNOHANG)) == 0) {
    	    if (elapsed >= SETUP_SCRIPT_TIMEOUT_SEC) {
    	        abort_run("setup",
    	            "setup script pid=%d ('%s') did not complete within %ds - likely hung.",
    	            plan->setup.pid, plan->setup.script, SETUP_SCRIPT_TIMEOUT_SEC);
    	    }
    	    sleep(1);
    	    elapsed++;
    	}
    	if (wp == -1) {
    	    perror("  [setup]  waitpid failed");
    	    abort_run("setup", "waitpid on setup pid=%d failed", plan->setup.pid);
    	} else if (WIFEXITED(status)) {
    	    int exit_code = WEXITSTATUS(status);
    	    if (exit_code != 0) {
    	        abort_run("setup",
    	            "setup script pid=%d ('%s') exited with status %d - the target "
    	            "binary/cluster was not correctly prepared.",
    	            plan->setup.pid, plan->setup.script, exit_code);
    	    }
    	    printf("  ✓ setup  pid=%d  exit_status=%d\n", plan->setup.pid, exit_code);
    	} else if (WIFSIGNALED(status)) {
    	    abort_run("setup", "setup script pid=%d killed by signal %d",
    	        plan->setup.pid, WTERMSIG(status));
    	} else {
    	    printf("  ? setup  pid=%d  ended (unknown reason)\n", plan->setup.pid);
    	}
	}
	//Sleep to let the started services/containers stabilize (unchanged) - for
	//live-cluster schedules the setup script itself (docker compose up -d)
	//already returns quickly, well before the cluster is actually ready, so
	//this warm-up sleep is still needed independent of the waitpid above.
	if(plan->setup.duration > 0){
	   printf("  [setup]  waiting for setup to start...\n");
	   sleep(plan->setup.duration);
	}
}

void start_workload(){
		if (!plan)
			return;
		if(plan->workload.pid == 0)
			return;
		printf("  [workload]  started  pid=%d  %s\n",plan->workload.pid,plan->workload.script);
		kill(plan->workload.pid,SIGUSR1);
}


void start_pre_workload(){
	if (!plan)
		return;
	if(plan->pre_workload.pid == 0)
		return;
	printf("  [pre-work]  started  pid=%d\n",plan->pre_workload.pid);
	kill(plan->pre_workload.pid,SIGUSR1);

    int status;

    printf("  [pre-work]  waiting for completion...\n");

    if (waitpid(plan->pre_workload.pid, &status, 0) == -1) {
            perror("waitpid failed");
        } else {
            if (WIFEXITED(status)) {
                printf("  ✓ pre-workload  pid=%d  exit_status=%d\n", plan->pre_workload.pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("  ✗ pre-workload  pid=%d  killed by signal %d\n", plan->pre_workload.pid, WTERMSIG(status));
            } else {
                printf("  ? pre-workload  pid=%d  ended (unknown reason)\n", plan->pre_workload.pid);
            }
        }
}
//Starts the lazyfs process in the background
void start_lazyfs(){
	//Start workload
	if (!plan)
		return;
	if(plan->lazyfs.pid == 0)
		return;

	printf("  [lazyfs]  started  pid=%d\n",plan->lazyfs.pid);
	kill(plan->lazyfs.pid,SIGUSR1);
}

//TODO: Collect container pids, waits until they start
void collect_container_pids(){
	// Bounded retry with backoff: an earlier version of this loop had no
	// sleep and no limit at all, spinning as fast as fork/exec allows
	// (shelling out to `docker inspect` on every single iteration) whenever
	// even one container was briefly not yet inspectable right after
	// `docker compose up` reports "Started" - a real, observed Docker
	// timing gap, not hypothetical. That produced tens of thousands of
	// "no such object" errors per minute and never gave up, hanging the
	// whole run (confirmed: had to force-kill the executor process tree
	// after it spun long past the schedule's own maximum_time). 100ms
	// between attempts, up to 30s total, matches the timescale containers
	// actually need to become inspectable and fails loudly instead of
	// silently hanging forever.
	int node_count = 0;
	int attempts = 0;
	const int max_attempts = 300; // 300 * 100ms = 30s
	while (node_count != NODE_COUNT && attempts < max_attempts){
		node_count = 0;
		for(int i=0; i < NODE_COUNT;i++){
			if (nodes[i].container){
			    int container_pid = 0;
				if (nodes[i].container_type == CONTAINER_TYPE_DOCKER || nodes[i].container_type == CONTAINER_TYPE_DOCKER_AUTOMATIC){
					container_pid = get_docker_container_pid(nodes[i].name);
				}
				if (nodes[i].container_type == CONTAINER_TYPE_LXC){
					container_pid = get_lxc_container_pid(nodes[i].name);
				}
				nodes[i].container_pid = container_pid;
				if(nodes[i].container_pid){
					nodes[i].pid = nodes[i].container_pid;
					nodes[i].current_pid = nodes[i].container_pid;
					node_count++;
				}
			}
			else{
				node_count++;
			}
		}
		if (node_count != NODE_COUNT){
			attempts++;
			usleep(100000);
		}
	}
	if (node_count != NODE_COUNT){
		fprintf(stderr, "  [collect_container_pids]  ERROR: only %d/%d containers became inspectable after 30s - continuing anyway, but node PIDs for the rest are 0/invalid\n", node_count, NODE_COUNT);
	}
}

// Applies each node's optional baseline network latency (nodes[i].latency_ms/
// jitter_ms, from the schedule's `nodes.*.latency_ms`/`jitter_ms` - see
// schedule_parser/nodes.py) via `tc qdisc ... netem` inside the container's
// own network namespace - the SAME nsenter-into-container-netns pattern
// setup_tc_progs()'s BLOCK_IPS handling already uses (network_manager
// relies on the identical fact: Docker always numbers a fresh container's
// own interface ifindex 2/"eth0" inside its netns). Deliberately NOT a
// fault: this is a permanent environmental property applied once here,
// before any node script is launched, living for the whole run - no
// condition-gating, no duration tracking, no removal logic. Destroyed
// automatically when `docker compose down` tears the container down at the
// start of the next run.
void apply_node_latency(){
	for (int i = 0; i < NODE_COUNT; i++){
		if (!nodes[i].container || nodes[i].latency_ms <= 0){
			continue;
		}
		if (!nodes[i].container_pid){
			fprintf(stderr, "  [latency]  node=%s  skipped - no container_pid\n", nodes[i].name);
			continue;
		}

		char target[16];
		snprintf(target, sizeof(target), "%d", nodes[i].container_pid);
		char delay[16];
		snprintf(delay, sizeof(delay), "%dms", nodes[i].latency_ms);
		char jitter[16];
		snprintf(jitter, sizeof(jitter), "%dms", nodes[i].jitter_ms);

		char *args[] = {"nsenter", "--target", target, "--net", "--",
			"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", delay, jitter, NULL};

		pid_t pid;
		FILE *fp = custom_popen("nsenter", args, NULL, 'r', &pid, 1);
		if (fp){
			int status;
			waitpid(pid, &status, 0);
			fclose(fp);
		}

		printf("  [latency]  node=%s  delay=%s  jitter=%s\n", nodes[i].name, delay, jitter);
	}
}

void setup_node_scripts(){
	for(int i=0;i<NODE_COUNT;i++){
		if(!nodes[i].script[0]){
			//printf("No command in this node %d \n",i);
			continue;
		}
		if (!strlen(nodes[i].script)){
			printf("  [node]  node[%d] empty command, skipping\n",i);
			continue;
		}

		if (nodes[i].container){
		    if (!strlen(nodes[i].pid_file)){
				printf("  [node]  node[%d]  command=%s\n",i,nodes[i].script);
				start_target_process_in_container(i,&nodes[i].pid);
			}
		}
		else if (!nodes[i].container){
			start_target_process(i,&nodes[i].pid);
			printf("  [node]  node[%d]  pid=%d\n",i,nodes[i].pid);
			nodes[i].current_pid = nodes[i].pid;
			int one = 1;
			bpf_map_update_elem(constants.pids, &nodes[i].current_pid, &one, BPF_ANY);
		}
	}
}

void collect_container_processes(){
    printf("  [collect]  gathering container process pids\n");
	for(int i = 0; i< NODE_COUNT; i++){
		if (nodes[i].container && strlen(nodes[i].script) > 0 && !(strlen(nodes[i].pid_file))){
		    //The pid is now the pid of the process we started with popen, not of the node
			int process_pid = nodes[i].pid;
			nodes[i].pid = process_pid;
			nodes[i].current_pid = process_pid;
		}
		if (nodes[i].container){
		     //If the node pid is in a file inside the container check for it
          	 if (strlen(nodes[i].pid_file)){
                char *dir;
                if (nodes[i].container_type == CONTAINER_TYPE_DOCKER || nodes[i].container_type == CONTAINER_TYPE_DOCKER_AUTOMATIC){
                    dir = get_docker_container_location(nodes[i].name);
                }
                if (nodes[i].container_type == CONTAINER_TYPE_LXC){
                    dir = get_lxc_container_location(nodes[i].name);
                }

                char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
                snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, nodes[i].pid_file);

                // Wait until file contains the pid
                struct stat st;
                while (1) {
                    if (stat(combined_path, &st) == 0) {
                        if (st.st_size > 0) {
                            break;
                        }
                    }
                    sleep_for_ms(10);
                }
                FILE *file;
                file = fopen(combined_path, "r");
                if (file == NULL) {
                    perror("Error opening file");
                    return;
                }
                int pid;
                if (fscanf(file, "%d", &pid) == 1) {
                    printf("  [collect]  pid in file: %d\n", pid);
                } else {
                    printf("  ✗ failed to read pid from file\n");
                }

                int host_pid = find_host_pid_for_container_pid(pid);
                printf("  [collect]  node[%d]  host_pid=%d\n",i,host_pid);
                nodes[i].pid = host_pid;
                nodes[i].current_pid = host_pid;
                //TODO: This basically means redpanda can't setup in time for our experiment messes everything up
                //send_signal(host_pid,SIGSTOP,nodes[i].name);
                int one = 1;
			    bpf_map_update_elem(constants.pids, &nodes[i].current_pid, &one, BPF_ANY);
                fclose(file);
                continue;
            }
		}
	}
}

//Sends the info of the nodes to the tracer.
//If it is a container the pid right now is of the script, not of the node itself.
void send_info_to_tracer(){
	for(int i = 0; i< NODE_COUNT; i++){
			if(nodes[i].container){
				nodes[i].if_index = get_interface_index(nodes[i].veth);
				send_node_and_pid_to_tracer(nodes[i].container_pid,nodes[i].container_type,nodes[i].current_pid,nodes[i].name,nodes[i].if_index);
			}
			else{
				send_node_and_pid_to_tracer(nodes[i].container_pid,0,nodes[i].current_pid,nodes[i].name,nodes[i].if_index);
			}
	}
}

void send_node_and_pid_to_tracer(int container_pid,int container_type,int pid, char* node_name,int if_index){
		char message[256];
		snprintf(message,sizeof(message),"%s,%d,%d,%d,%d\n",node_name,container_pid,pid,if_index,container_type);
		if (write(deployment_tracer->pipe_write_end, message, strlen(message)) == -1) {  // +1 to include the null terminator
            perror("write");
            close(deployment_tracer->pipe_write_end);
            exit(EXIT_FAILURE);
        }
        char buffer[16];
        ssize_t bytesRead;
        bytesRead = read(deployment_tracer->pipe_read_end, buffer, sizeof(buffer) - 1);

        if (bytesRead == -1) {
            perror("read");
            close(deployment_tracer->pipe_read_end);
            exit(EXIT_FAILURE);
        } else if (bytesRead == 0) {
            fprintf(stderr, "read returned EOF while waiting for tracer acknowledgment\n");
            close(deployment_tracer->pipe_read_end);
            exit(EXIT_FAILURE);
        }

        /* Null-terminate if needed (not used here) */
        buffer[bytesRead] = '\0';

        //This should contain a message called done
        //printf("ROSE->TRACER: %s", buffer);
}

void start_nodes_scripts(){
    printf("  [nodes]  sending SIGUSR1 to non-container nodes\n");
	for(int i=0;i<NODE_COUNT;i++){
		if (!(nodes[i].container)){
			kill(nodes[i].pid,SIGUSR1);
		}
	}
}
void start_container_nodes_scripts(){
	print_block("CONTAINER SCRIPTS: STARTED");
	for(int i=0;i<NODE_COUNT;i++){
		if (nodes[i].container && !(strlen(nodes[i].pid_file)) && nodes[i].container_type != CONTAINER_TYPE_DOCKER_AUTOMATIC){
			kill(nodes[i].pid,SIGUSR1);
			//Need to have the pid of the process inside the container
			//TODO: DOES NOT WORK FOR LXC
			int one = 1;
			retrieve_new_pid_container(i, nodes[i].pid);
			bpf_map_update_elem(constants.pids, &nodes[i].current_pid, &one, BPF_ANY);
			nodes[i].pid = nodes[i].current_pid;
		}
		if (nodes[i].container && nodes[i].container_type == CONTAINER_TYPE_DOCKER_AUTOMATIC){
		    //TODO: Implement this
    		// bpf_map_update_elem(constants.pids, &nodes[i].current_pid, &one, BPF_ANY);
    		// nodes[i].pid = nodes[i].current_pid;
		}
		if(nodes[i].pid_tc_in !=0){
		    printf("  [tc]  starting TC prog (in)   node[%d]\n",i);
			kill(nodes[i].pid_tc_in,SIGUSR1);
		}
		if(nodes[i].pid_tc_out !=0){
		    printf("  [tc]  starting TC prog (out)  node[%d]\n",i);
			kill(nodes[i].pid_tc_out,SIGUSR1);
		}
	}
}

FILE* start_target_process(int node_number, int *pid){

	printf("  [node]  starting  %s  script=%s\n",nodes[node_number].name,nodes[node_number].script);

	char script[STRING_SIZE];

	char *args_script[STRING_SIZE];

	char *env_script[STRING_SIZE];

	char *token = strtok(nodes[node_number].script," ");

	strcpy(script,token);

	//Create args
	args_script[0]=(char*)malloc(STRING_SIZE*sizeof(char));
	strcpy(args_script[0],token);
	//printf("Args_script[0] is %s \n",args_script[0]);
	int pos = 1;

	token = strtok(NULL," ");

	while( token != NULL ) {

		args_script[pos]=(char*)malloc(STRING_SIZE*sizeof(char));

		strcpy(args_script[pos],token);

		//printf("Added %s to arg of %s",args_script[pos],nodes[node_number].name);

		token = strtok(NULL," ");
		pos++;
   	}

	args_script[pos]= NULL;

	//Create ENV variables
	// strtok mutates its input and this runs again on every relaunch, so
	// tokenize a private copy. An empty env yields just the NULL terminator.
	char *env_copy = strdup(nodes[node_number].env);
	char *env_save = NULL;
	int pos_env = 0;
	for (char *token_env = strtok_r(env_copy," ",&env_save); token_env != NULL && pos_env < STRING_SIZE-1; token_env = strtok_r(NULL," ",&env_save)){
		env_script[pos_env++] = strdup(token_env);
	}
   	env_script[pos_env]= NULL;
	free(env_copy);

	FILE *fp = custom_popen(script,args_script,env_script,'r',pid,0);

	if (!fp)
    {
        perror("popen failed:");
        exit(1);
    }

	pthread_t thread_id;

	struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

	args->fp= fp;
	args->pid = pid;
	// Relay a non-container node's stdout into the executor's stdout (-> run_schedule.log).
	// violet's unit-test node prints its VIOLET_RESULT line there and reads it back via
	// read_violet_result(); without this drain the pipe is never read and that line is lost.
	pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);

	return fp;

}

FILE* start_target_process_in_container(int node_number,int *pid){

	// Prepare the nsenter command and arguments
	char *pid_str = malloc(16);
	snprintf(pid_str, 16, "%d", nodes[node_number].container_pid);
	char *env_script[STRING_SIZE];

	char **nsenter_args = build_nsenter_args(pid_str,nodes[node_number].container_type);

	char *token = strtok(nodes[node_number].script," ");

	int index;
	if (nodes[node_number].container_type == CONTAINER_TYPE_DOCKER) {
    	nsenter_args[10] = token;

    	index = 10;
	}
	if (nodes[node_number].container_type == CONTAINER_TYPE_LXC) {
    	nsenter_args[10] = token;

    	index = 10;
	}

	token = strtok(NULL," ");

	while( token != NULL ) {
		index++;
		nsenter_args[index]=token;
		token = strtok(NULL," ");
   	}
	index++;
	nsenter_args[index] = NULL;

	//Create ENV variables
	// strtok mutates its input and this runs again on every relaunch, so
	// tokenize a private copy. An empty env yields just the NULL terminator.
	char *env_copy = strdup(nodes[node_number].env);
	char *env_save = NULL;
	int pos_env = 0;
	for (char *token_env = strtok_r(env_copy," ",&env_save); token_env != NULL && pos_env < STRING_SIZE-1; token_env = strtok_r(NULL," ",&env_save)){
		env_script[pos_env++] = strdup(token_env);
	}
   	env_script[pos_env]= NULL;
	free(env_copy);

	// Migrate the about-to-be-launched process into this container's own
	// cgroup (derived from the container's real host pid) right before
	// nsenter runs - nsenter --mount alone does not change cgroup
	// membership, which tidb-server/pd-server need correct at process-init
	// time (see migrate_self_into_container_cgroup()'s comment in aux.c).
	// Only for Docker; LXC safely no-ops (pid 0).
	pid_t cgroup_container_pid = (nodes[node_number].container_type == CONTAINER_TYPE_DOCKER)
		? nodes[node_number].container_pid : 0;

	FILE *fp;
	if(nodes[node_number].running){
		fp = custom_popen_cgroup("nsenter",nodes[node_number].args,env_script,'r',pid,0,cgroup_container_pid);
		fclose(nodes[node_number].read_end);
		nodes[node_number].read_end = fp;
	}
	else{
		fp = custom_popen_cgroup("nsenter",nsenter_args,env_script,'r',pid,0,cgroup_container_pid);
		nodes[node_number].read_end = fp;
		nodes[node_number].running = 1;
		nodes[node_number].args = nsenter_args;
	}
	if (!fp)
    {
        perror("popen failed:");
        exit(1);
    }

	printf("  [node]  started  %s  ns_pid=%d  pid=%d  script=%s\n",nodes[node_number].name,nodes[node_number].container_pid,*pid,nodes[node_number].script);
	pthread_t thread_id;
	struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));
	args->fp= fp;
	args->pid = pid;
	//pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	return fp;
}


void setup_begin_conditions(){

	print_block("Adding relevant conditions, file_names and uprobes to kernel");
	int user_func_cond_nr = 0;
	constants.mode = NORMAL;
	for(int i = 0; i < FAULT_COUNT; i++){
		int has_time_condition = 0;
		int has_fault_dep_condition = 0;
		for(int j = 0; j <faults[i].relevant_conditions;j++){
			int type = faults[i].fault_conditions_begin[j].type;
			int traced = faults[i].traced;
			int pid = nodes[traced].pid;
			int error;

			if(type == SYSCALL){

				system_call syscall = faults[i].fault_conditions_begin[j].condition.syscall;
				int syscall_nr = syscall.syscall;
				insert_relevant_condition_in_ebpf(i,pid,syscall_nr,syscall.call_count);
			}
			if (type == FILE_SYSCALL){

				file_system_call syscall = faults[i].fault_conditions_begin[j].condition.file_system_call;

				struct file_info_simple file_info = {};
				if (strlen(syscall.file_name)){
				    snprintf(file_info.filename,sizeof(file_info.filename),"%s",syscall.file_name);
					//strncpy(file_info.filename,syscall.file_name,sizeof(file_info.filename));
					file_info.size = strlen(file_info.filename);
					printf("  [cond]  fileinfo  name=%s  len=%d\n",file_info.filename,file_info.size);
				}

				int syscall_nr = syscall.syscall;

				struct info_key info_key = {
					pid,
					syscall_nr
				};

				error = bpf_map_update_elem(constants.files,&info_key,&file_info,BPF_ANY);
				if (error){
					printf("  ✗ map update (files) err=%d  file=%s\n",error,file_info.filename);
				}

				struct relevant_fds relevant_fd_init = {};

				error = bpf_map_update_elem(constants.relevant_fd,&pid,&relevant_fd_init,BPF_ANY);
				if (error){
					printf("  ✗ map update (fd) err=%d  pid=%d\n",error,pid);
				}

				insert_relevant_condition_in_ebpf(i,pid,syscall_nr,syscall.call_count);

			}
			if(type == USER_FUNCTION){
				//user_func_cond_nr is the position where the call_count will reside in fault_type_conditions
				user_function user_function = faults[i].fault_conditions_begin[j].condition.user_function;
				insert_relevant_condition_in_ebpf(i,pid,faults[i].fault_conditions_begin[j].condition.user_function.cond_nr,user_function.call_count);
				user_func_cond_nr++;
			}
			if(type == TIME){
				int time = faults[i].fault_conditions_begin[j].condition.time;
				faults[i].initial.fault_type_conditions[TIME_STATE] = time;
				has_time_condition = time;

				if (faults[i].target == -2){
					for (int i = 0; i < NODE_COUNT; i++){
						insert_relevant_condition_in_ebpf(i,nodes[i].current_pid,TIME_STATE,1);
					}
				}else{
					insert_relevant_condition_in_ebpf(i,pid,TIME_STATE,1);
				}
			}
			if(type == FAULT_CONDITION){
				has_fault_dep_condition = 1;
			}
		}
		if (has_time_condition)
			constants.mode |= TIME_DEP;
		if (has_fault_dep_condition)
			constants.mode |= FAULT_DEP;

		// if (faults[i].target == -1){
		// 	for(int i = 0; i < NODE_COUNT; i++){
		// 		if (nodes[i].leader_probe)
		// 			continue;
		// 		if(nodes[i].container){
		// 			//Find the directory in hostnamespace
		// 			char *dir;
		// 			if (nodes[i].container_type == CONTAINER_TYPE_DOCKER)
		// 			   dir = get_docker_container_location(nodes[i].name);
		// 			if (nodes[i].container_type == CONTAINER_TYPE_LXC)
		// 			   dir = get_lxc_container_location(nodes[i].name);

		// 			//Combine paths
		// 			char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
		// 			snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, nodes[i].binary);
		// 			nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,combined_path,FAULT_COUNT,0,constants.mode & TIME_DEP, 1,0);
		// 		}else{
		// 			nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,nodes[i].leader_symbol,FAULT_COUNT,0,constants.mode & TIME_DEP, 1,0);
		// 		}
		// 	}
		// }




	}
}
void setup_uprobes(){
    printf("\n  [uprobe]  setting up user-function probes\n");
    int user_func_cond_nr = 0;
    for(int i = 0; i < FAULT_COUNT; i++){
		int has_time_condition = 0;
		for(int j = 0; j < faults[i].relevant_conditions;j++){
			int type = faults[i].fault_conditions_begin[j].type;
			int traced = faults[i].traced;
			int pid = nodes[traced].pid;
			int error;
			if(type == USER_FUNCTION){
				//user_func_cond_nr is the position where the call_count will reside in fault_type_conditions
				user_function user_function = faults[i].fault_conditions_begin[j].condition.user_function;
				faults[i].fault_conditions_begin[j].condition.user_function.cond_nr = user_func_cond_nr+STATE_PROPERTIES_COUNT;

				insert_relevant_condition_in_ebpf(i,pid,faults[i].fault_conditions_begin[j].condition.user_function.cond_nr,user_function.call_count);

				if(nodes[traced].container){
					//Find the directory in hostnamespace
					char* dir;
					if (nodes[traced].container_type == CONTAINER_TYPE_DOCKER)
					   dir = get_docker_container_location(nodes[traced].name);
					if (nodes[traced].container_type == CONTAINER_TYPE_LXC)
					   dir = get_lxc_container_location(nodes[traced].name);
					//Combine paths
					char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
					snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, user_function.binary_location);

					printf("  [uprobe]  attached  %s  in %s\n",user_function.symbol,combined_path);

					faults[i].list_of_functions[user_func_cond_nr] = uprobe(pid,user_function.symbol,combined_path,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.mode,0,user_function.offset,user_function.absolute_offset);
					if (!faults[i].list_of_functions[user_func_cond_nr]) {
						abort_run("uprobe", "failed to attach uprobe for fault %d: symbol='%s' binary='%s'", i, user_function.symbol, combined_path);
					}
				}else{
					faults[i].list_of_functions[user_func_cond_nr] = uprobe(pid,user_function.symbol,user_function.binary_location,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.mode,0,user_function.offset,user_function.absolute_offset);
					if (!faults[i].list_of_functions[user_func_cond_nr]) {
						abort_run("uprobe", "failed to attach uprobe for fault %d: symbol='%s' binary='%s'", i, user_function.symbol, user_function.binary_location);
					}
				}
				user_func_cond_nr++;
			}
		}

		if (faults[i].target == -1){
			for(int i = 0; i < NODE_COUNT; i++){
				if (nodes[i].leader_probe)
					continue;
				if(nodes[i].container){
					//Find the directory in hostnamespace
					char *dir;
					if (nodes[i].container_type == CONTAINER_TYPE_DOCKER)
					   dir = get_docker_container_location(nodes[i].name);
					if (nodes[i].container_type == CONTAINER_TYPE_LXC)
					   dir = get_lxc_container_location(nodes[i].name);

					//Combine paths
					char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
					snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, nodes[i].binary);
					nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,combined_path,FAULT_COUNT,0,constants.mode, 1,0,false);
					if (!nodes[i].leader_probe) {
						abort_run("uprobe", "failed to attach leader uprobe for node '%s': symbol='%s' binary='%s'", nodes[i].name, nodes[i].leader_symbol, combined_path);
					}
				}else{
					nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,nodes[i].leader_symbol,FAULT_COUNT,0,constants.mode, 1,0,false);
					if (!nodes[i].leader_probe) {
						abort_run("uprobe", "failed to attach leader uprobe for node '%s': symbol='%s'", nodes[i].name, nodes[i].leader_symbol);
					}
				}
			}
		}
		if (faults[i].target == -2){
			for(int i = 0; i < NODE_COUNT; i++){
				if (nodes[i].leader_probe)
					continue;
				if(nodes[i].container){
					//Find the directory in hostnamespace
					char *dir;
					if (nodes[i].container_type == CONTAINER_TYPE_DOCKER)
					   dir = get_docker_container_location(nodes[i].name);
					if (nodes[i].container_type == CONTAINER_TYPE_LXC)
					   dir = get_lxc_container_location(nodes[i].name);

					//Combine paths
					char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
					snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, nodes[i].binary);
					nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,combined_path,FAULT_COUNT,0,constants.mode, 1,0,false);
					if (!nodes[i].leader_probe) {
						abort_run("uprobe", "failed to attach leader uprobe for node '%s': symbol='%s' binary='%s'", nodes[i].name, nodes[i].leader_symbol, combined_path);
					}

				}else{
					nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,nodes[i].binary,FAULT_COUNT,0,constants.mode, 1,0,false);
					if (!nodes[i].leader_probe) {
						abort_run("uprobe", "failed to attach leader uprobe for node '%s': symbol='%s' binary='%s'", nodes[i].name, nodes[i].leader_symbol, nodes[i].binary);
					}
				}

			}
		}
	}
}

void insert_relevant_condition_in_ebpf(int fault_nr,int pid,int cond_nr,int call_count){
	int error;
	struct info_key information = {
		pid,
		cond_nr
	};
	struct info_state *new_information_state = (struct info_state*)malloc(sizeof(struct info_state));

	new_information_state->current_value = 0;

	new_information_state->relevant_states[fault_nr] = call_count;

	new_information_state->repeat = faults[fault_nr].repeat;

	printf("  [cond]  fault=%d  key=%d  value=%d  cond_match=%d  pid=%d\n",fault_nr,cond_nr,new_information_state->relevant_states[fault_nr],faults[fault_nr].initial.conditions_match[fault_nr],pid);
	struct info_state *old_information_state = (struct info_state*)malloc(sizeof(struct info_state));

	old_information_state->current_value = 0;

	int exists = 0;
	exists = bpf_map_lookup_or_try_init_user(constants.relevant_state_info_fd,&information,new_information_state,old_information_state);

	//if already exists add
	if(exists){
		old_information_state->relevant_states[fault_nr] = call_count;
		error = bpf_map_update_elem(constants.relevant_state_info_fd,&information,old_information_state,BPF_ANY);
		if (error){
			printf("  ✗ map update (cond) err=%d  key=%d\n",error,cond_nr);
		}
		free(new_information_state->relevant_states);
	}else{
		free(old_information_state->relevant_states);
	}
}

//Adds fault info eBPF Maps fault into simplified_fault
void add_faults_to_bpf(){
	print_block("Adding Faults to eBPF Maps");

	for (int i = 0; i < FAULT_COUNT; i++){
		printf("  [fault]  nr=%d  type=%d  pid=%d\n",i,faults[i].fault_type,nodes[faults[i].traced].pid);
		struct simplified_fault new_fault;
		new_fault.run = 0;
		new_fault.duration = faults[i].duration;
		new_fault.start_time = 0;
		new_fault.timestamp = 0;
		new_fault.fault_type = faults[i].fault_type;
		new_fault.done = faults[i].done;
		new_fault.quorum_size = QUORUM;
		new_fault.faults_done = 0;
		new_fault.pid = nodes[faults[i].traced].pid;

		new_fault.target = faults[i].target;

		if (faults[i].fault_type == BLOCK_IPS)
		  new_fault.target_if_index = get_interface_index(nodes[faults[i].target].veth)-1;
		new_fault.occurrences = faults[i].occurrences;
		new_fault.relevant_conditions = faults[i].relevant_conditions;
		new_fault.fault_nr = i;
		new_fault.repeat = faults[i].repeat;
		// "any" target (-3)/dynamic-group CAS gate - see bpf_shared.h's
		// comment above `claimed`/`group_leader_fault_nr`. Statically
		// compiled faults are never part of a dynamic reserved-slot group
		// (that's sunflower/rose_injector.py's own runtime-only concept),
		// so group_leader_fault_nr must be the explicit "not grouped" -1,
		// not left as stack garbage - state_processor.bpf.h's gate treats
		// any non-negative value as "look up and CAS on that other slot".
		new_fault.claimed = 0;
		new_fault.group_leader_fault_nr = -1;

		for(int k = 0; k < (STATE_PROPERTIES_COUNT+MAX_FUNCTIONS); k++){
			new_fault.initial.conditions_match[k] = 0;
			new_fault.initial.fault_type_conditions[k] = 0;
		}
		for(int k = 0; k < MAX_FAULT_DEPS; k++){
			new_fault.initial.dependency_fault_nrs[k] = -1;
			new_fault.initial.dependency_satisfied[k] = 0;
		}

		for(int j = 0; j <faults[i].relevant_conditions;j++){
			int type = faults[i].fault_conditions_begin[j].type;
			if(type == SYSCALL){
				system_call syscall = faults[i].fault_conditions_begin[j].condition.syscall;
				int cond_nr = syscall.syscall;
				new_fault.initial.fault_type_conditions[cond_nr] = syscall.call_count;
				printf("  [condition]  fault=%d  syscall=%d  count=%d\n",i,cond_nr,syscall.call_count);
			}
			if (type == FILE_SYSCALL){
				file_system_call syscall = faults[i].fault_conditions_begin[j].condition.file_system_call;
				int cond_nr = syscall.syscall;
				new_fault.initial.fault_type_conditions[cond_nr] = syscall.call_count;
				printf("  [condition]  fault=%d  file_syscall=%d  count=%d\n",i,cond_nr,syscall.call_count);
			}
			if(type == USER_FUNCTION){
				user_function user_function = faults[i].fault_conditions_begin[j].condition.user_function;
				int cond_nr = user_function.cond_nr;
				new_fault.initial.fault_type_conditions[cond_nr] = user_function.call_count;
				printf("  [condition]  fault=%d  fn=%s  id=%d  count=%d\n",i,user_function.symbol,cond_nr,user_function.call_count);
			}
			if(type == TIME){
				new_fault.initial.fault_type_conditions[TIME_STATE] = faults[i].fault_conditions_begin[j].condition.time;
				printf("  [condition]  fault=%d  time=%d\n",i,faults[i].fault_conditions_begin[j].condition.time);
			}
			if(type == FAULT_CONDITION){
				fault_dependency dep = faults[i].fault_conditions_begin[j].condition.fault_dep;
				for(int k = 0; k < MAX_FAULT_DEPS; k++){
					if(new_fault.initial.dependency_fault_nrs[k] == -1){
						new_fault.initial.dependency_fault_nrs[k] = dep.fault_nr;
						printf("  [condition]  fault=%d  depends_on=%d\n",i,dep.fault_nr);
						break;
					}
				}
			}
		}

		if (faults[i].category == SYSCALL_FAULT){
			new_fault.return_value = faults[i].fault_details.syscall.return_value;
		}
		if (faults[i].category == KERNEL_FAULT){
			// Reuses the generic return_value slot to carry the truncated byte
			// count (or, for TORN_READ_FAULT, the corruption offset) through to
			// the BPF map, the same way SYSCALL_FAULT reuses it for its own
			// per-category meaning. Read back by state_processor.
			// bpf.h's inject_fault() to arm the matching rose.ko kfunc.
			if (faults[i].fault_type == PARTIAL_WRITE_FAULT){
				new_fault.return_value = faults[i].fault_details.partial_write_fault.count;
				new_fault.corrupt_buffer = faults[i].fault_details.partial_write_fault.corrupt_buffer;
			}
			if (faults[i].fault_type == PARTIAL_READ_FAULT){
				new_fault.return_value = faults[i].fault_details.partial_read_fault.count;
			}
			if (faults[i].fault_type == TORN_READ_FAULT){
				new_fault.return_value = faults[i].fault_details.torn_read_fault.offset;
			}
		}

		//TODO GO OVER FAULT DETAILS

		int error = bpf_map_update_elem(constants.bpf_map_fault_fd,&i,&new_fault,BPF_ANY);
		if (error)
			printf("  ✗ map update (fault bpf) err=%d  fault=%d\n",error,i);
	}

}

// network_manager/network_manager is built to src/network_manager/network_manager
// by the Makefile, while this binary itself is built to src/executor/executor
// (see the "-o executor/executor" and "-o network_manager/network_manager"
// rules) - the two are siblings under src/, not parent/child. Resolve it
// relative to this binary's own on-disk location via /proc/self/exe rather
// than the executor process's current working directory - the executor is
// commonly launched from an unrelated CWD (e.g. /vagrant/), where a plain
// relative "./network_manager/network_manager" silently resolves to the
// wrong path.
static void get_network_manager_path(char *out, size_t out_size){
	char exe_path[PATH_MAX];
	ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len == -1){
		// Fall back to the old CWD-relative behavior if /proc/self/exe is
		// somehow unavailable.
		snprintf(out, out_size, "./network_manager/network_manager");
		return;
	}
	exe_path[len] = '\0';

	char exe_path_copy[PATH_MAX];
	strncpy(exe_path_copy, exe_path, sizeof(exe_path_copy) - 1);
	exe_path_copy[sizeof(exe_path_copy) - 1] = '\0';

	// First dirname() strips the filename, leaving .../src/executor (this
	// binary's own directory). Second strips that, leaving .../src, where
	// network_manager/ actually sits as a sibling of executor/.
	char *exe_dir = dirname(exe_path_copy);

	char exe_dir_copy[PATH_MAX];
	strncpy(exe_dir_copy, exe_dir, sizeof(exe_dir_copy) - 1);
	exe_dir_copy[sizeof(exe_dir_copy) - 1] = '\0';

	char *src_dir = dirname(exe_dir_copy);
	snprintf(out, out_size, "%s/network_manager/network_manager", src_dir);
}

//Create TC programs, one for each interface
int setup_tc_progs(){
	print_block("STARTING TC PROGRAMS");
	int handle = 5;
	//Insert IPS to block in a network device, key->if_index value->list of ips
	int tc_ebpf_progs_counter = 0;

	char nsenter[] = "nsenter";
	char *nsenter_args[11];

	for(int i =0; i < 11; i++){
		nsenter_args[i]=(char*)malloc(STRING_SIZE*sizeof(char));
	}

	strcpy(nsenter_args[0],"nsenter");
	strcpy(nsenter_args[1],"-t");
	strcpy(nsenter_args[3],"-n");
	get_network_manager_path(nsenter_args[4], STRING_SIZE);
	nsenter_args[10] = NULL;

	char *env_script[STRING_SIZE];

	env_script[0] = NULL;

	for (int i =0;i<FAULT_COUNT;i++){

		if(faults[i].fault_type == BLOCK_IPS){

			int target = faults[i].target;
			int index = get_interface_index(nodes[target].veth);
			__be32 ips_to_block_out[MAX_IPS_BLOCKED] = {0};

			for (int k = 0; k < faults[i].fault_details.block_ips.count_out; k++){
				__be32 ip = faults[i].fault_details.block_ips.nodes_out[k];
				if(ip){
					char str[INET_ADDRSTRLEN];
					inet_ntop(AF_INET,&ip, str, INET_ADDRSTRLEN);
					ips_to_block_out[k]=ip;
				}
			}
			//In containers the index inside is always -1 from the one in the host namespace
			__u32 index_in_unsigned = 0;
			if (nodes[target].container){
			    if (nodes[target].container_type == CONTAINER_TYPE_DOCKER || nodes[target].container_type == CONTAINER_TYPE_DOCKER_AUTOMATIC){
			        index_in_unsigned = (__u32)2;
			    }if(nodes[target].container_type == CONTAINER_TYPE_LXC){
					index_in_unsigned = (__u32)index-1;
				}
			}

			struct tc_key egress_key = {
				index-1,
				BPF_TC_EGRESS,
				i
			};

			int error = bpf_map_update_elem(constants.blocked_ips,&egress_key,&ips_to_block_out,BPF_ANY);
			if (error){
				printf("  ✗ map update (blocked_ips egress) err=%d  if_index=%d\n",error,index);
			}

			sprintf(nsenter_args[2], "%d", nodes[target].container_pid);
			sprintf(nsenter_args[5], "%u", index_in_unsigned);
			sprintf(nsenter_args[6], "%d", index-1);
			sprintf(nsenter_args[7], "%d", tc_ebpf_progs_counter+handle);
			sprintf(nsenter_args[8], "%d", FAULT_COUNT);
			sprintf(nsenter_args[9], "%d", BPF_TC_EGRESS);


			FILE *fp = custom_popen(nsenter,nsenter_args,env_script,'r',&(nodes[target].pid_tc_out),0);

			pthread_t thread_id;

			struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

			args->fp= fp;
			args->pid = &nodes[target].pid_tc_out;
			//pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);

			tc_ebpf_progs_counter++;

			pthread_t thread_id2;


			//printf("TC PROGRAM NUMBER: %d, INDEX: %d, NETWORK_DIRECTION: %d\n",tc_ebpf_progs_counter,index,BPF_TC_INGRESS);

			__be32 ips_to_block_in[MAX_IPS_BLOCKED] = {0};

			for (int k = 0; k < faults[i].fault_details.block_ips.count_in; k++){

				//TODO FIX IPS_BLOCKED LIST
				__be32 ip = faults[i].fault_details.block_ips.nodes_in[k];

				if(ip){

					char str[INET_ADDRSTRLEN];

					inet_ntop(AF_INET,&ip, str, INET_ADDRSTRLEN);

					ips_to_block_in[k]=ip;
				}
			}


			struct tc_key ingress_key = {
				index-1,
				BPF_TC_INGRESS,
				i
			};

			error = bpf_map_update_elem(constants.blocked_ips,&ingress_key,&ips_to_block_in,BPF_ANY);
			if (error){
				printf("  ✗ map update (blocked_ips ingress) err=%d  if_index=%d\n",error,index);
			}


			sprintf(nsenter_args[6], "%d", index-1);
			sprintf(nsenter_args[7], "%d", tc_ebpf_progs_counter+handle);
			sprintf(nsenter_args[9], "%d", BPF_TC_INGRESS);

			FILE *fp2 = custom_popen(nsenter,nsenter_args,env_script,'r',&(nodes[target].pid_tc_in),0);

			struct process_args *args2 = (struct process_args*)malloc(sizeof(struct process_args));

			args2->fp= fp2;
			args2->pid = &nodes[target].pid_tc_in;

			pthread_create(&thread_id2, NULL, (void *)print_output, (void*)args2);

			tc_ebpf_progs_counter++;

		}
		//TODO: Implement these later (useless for our current approach)
		if (faults[i].fault_type == NETWORK_ISOLATION){
		}
		if(faults[i].fault_type == DROP_PACKETS){

		}



	}
	return 0;
}

void count_time(){

    int time=0;
	int maximum_time = 1000 * get_maximum_time();
	printf("\n  [time]  started  max=%dms\n",maximum_time);
	while(1){
		sleep_for_ms(10);
		time += 10;

		for (int i = 0; i< FAULT_COUNT;i++){
			int fault_time = faults[i].initial.fault_type_conditions[TIME_STATE];
			if (fault_time == 0)
			    continue;
			if (((time % fault_time == 0) && faults[i].initial.fault_type_conditions[TIME_STATE]) ){

				struct simplified_fault fault;
				int err_lookup;
				err_lookup = bpf_map_lookup_elem(constants.bpf_map_fault_fd, &i,&fault);
				if (err_lookup){
					printf("  ✗ [time]  map lookup failed  errno=%d\n",errno);
				}

				if (fault.done == fault.occurrences){
					continue;
				}
				if (fault.initial.conditions_match[TIME_STATE] > 0){
					continue;
				}
				//printf("Time value property is %d \n",fault.initial.conditions_match[TIME_STATE]);
				printf("  [time]  trigger  fault=%d\n",fault.fault_nr);
				fault.initial.conditions_match[TIME_STATE] = 1;
				fault.run+=1;
				int error = bpf_map_update_elem(constants.bpf_map_fault_fd,&i,&fault,BPF_ANY);
				if(error)
					printf("  ✗ [time]  map update failed  err=%d\n",error);

			}
		}
		//Check if faults are done
		// int err_lookup;
		// int done_count = 0;
		// for (int i = 0; i< FAULT_COUNT;i++){
		// 	struct simplified_fault fault;
  //    			err_lookup = bpf_map_lookup_elem(constants.bpf_map_fault_fd, &i,&fault);
		// 	if(err_lookup){
		// 		printf("DID NOT FIND FAULT IN EBPF MAP, ERROR: %d \n",errno);
		// 	}

		// 	if (fault.done){
		// 		done_count++;
		// 	}
		// }

		// if (done_count != 0 && done_count == FAULT_COUNT){
		// 	printf("ROSE: FAULTS DONE \n");
		// 	exiting = true;
		// 	break;
		// }


		if (time >= maximum_time){
			printf("\n  [time]  maximum time reached, exiting\n");
			exiting = true;
			break;
		}

	}

}

// Appends "::key=value" to msg (bounded by msg_size) if value is non-empty. Builds up
// LazyFS pipe commands (lazyfs::torn-op::..., lazyfs::torn-seq::...) from only the
// fields the schedule YAML actually set, matching LazyFS's `key=value` pipe protocol.
static void append_lazyfs_param(char *msg, size_t msg_size, const char *key, const char *value){
	if (value[0] == '\0'){
		return;
	}
	size_t len = strlen(msg);
	snprintf(msg + len, msg_size - len, "::%s=%s", key, value);
}

//Handles events received from ringbuffer (eBPF)
int handle_event(void *ctx,void *data,long unsigned int data_sz)
{
	(void)ctx;
	(void)data_sz;

	const struct event *e = data;

	int fault_nr = e->fault_nr;
	switch(e->type){
		case PROCESS_STOP: {
			pthread_t thread_id;
			struct process_fault_args *args = (struct process_fault_args*)malloc(sizeof(struct process_fault_args));

			struct fault *fault = &faults[fault_nr];

			if (fault->target == -2 && fault->done == QUORUM){
				return 1;
			}

			if (fault->target == -1){
				printf("  [event]  PROCESS_STOP  leader  pid=%d\n",LEADER_PID);
				args->pid = LEADER_PID;
			}else{
				args->pid = e->pid;
			}

			args->duration = fault->duration;
			args->name = nodes[get_node_nr_from_pid(args->pid)].name;

			printf("  [event]  PROCESS_STOP  node=%s  duration=%d\n",args->name,fault->duration);

			pthread_create(&thread_id, NULL, (void*)pause_process, (void*)args);
			fault->done++;
			printf("  [fault]  fault[%d]  done=%d\n",fault_nr,fault->done);

			break;
		}
		case PROCESS_KILL:{

			pthread_t thread_id;
			struct process_fault_args *args = (struct process_fault_args*)malloc(sizeof(struct process_fault_args));
			struct fault *fault = &faults[fault_nr];

			if (fault->target == -2 && fault->done == QUORUM){
				return 1;
			}

			if (fault->target == -1){
				args->pid = LEADER_PID;
			}else{
				args->pid = e->pid;
			}


			int node_nr = get_node_nr_from_pid(e->pid);

			if (node_nr < 0){
			    printf("  ✗ [event]  PROCESS_KILL  node not found for pid=%d, fault not injected\n",e->pid);
				break;
			}

			args->duration = fault->duration;
			args->node_to_restart = node_nr;

			printf("  [event]  PROCESS_KILL  node=%s  pid=%d  duration=%d  fault=%d\n",nodes[(args->node_to_restart)].name,(args->pid),(args->duration),fault_nr);

			pthread_create(&thread_id, NULL, (void*)restart_process, (void*)args);
			fault->done++;
			break;
		}
		case LEADER_CHANGE:{
			LEADER_PID = e->pid;
			printf("  [event]  LEADER_CHANGE  new_leader_pid=%d\n",e->pid);
			int zero = 0;
			int error = bpf_map_update_elem(constants.auxiliary_info_map_fd,&zero,&LEADER_PID,BPF_ANY);
			if (error){
				printf("  ✗ map update (leader) err=%d\n",error);
			}
			break;
		}
		case CLEAR_CACHE:{
		    printf("  [event]  CLEAR_CACHE\n");
			FILE *file;
            file = fopen(plan->lazyfs.pipe_location, "w");

            if (file == NULL) {
                perror("Error opening file");
                break;
            }

            const char *msg = "lazyfs::clear-cache";
            size_t msg_len = sizeof("lazyfs::clear-cache");
            ssize_t _written = write(fileno(file), msg, msg_len);
            if (_written == -1) {
                perror("write failed");
            }

            fclose(file);

            printf("  ✓ lazyfs pipe written (clear-cache)\n");
            struct fault *fault = &faults[fault_nr];
            fault->done++;

            break;
		}
        case TORN_OP:{
   	        printf("  [event]  TORN_OP\n");
			struct fault *fault = &faults[fault_nr];
			lazyfs_fault *lf = &(fault->fault_details.lazyfs_fault);

			char msg[2048];
			snprintf(msg, sizeof(msg), "lazyfs::torn-op");
			append_lazyfs_param(msg, sizeof(msg), "file", lf->file);
			append_lazyfs_param(msg, sizeof(msg), "parts", lf->parts);
			append_lazyfs_param(msg, sizeof(msg), "parts_bytes", lf->parts_bytes);
			append_lazyfs_param(msg, sizeof(msg), "persist", lf->persist);

    		FILE *file;
            file = fopen(plan->lazyfs.pipe_location, "w");

            if (file == NULL) {
                perror("Error opening file");
                break;
            }
            size_t msg_len = strlen(msg) + 1;
            ssize_t _written = write(fileno(file), msg, msg_len);
            if (_written == -1) {
                perror("write failed");
            }

            fclose(file);

            printf("  ✓ lazyfs pipe written (torn-op): %s\n", msg);
            fault->done++;

            break;
        }
        case TORN_SEQ:{
   	        printf("  [event]  TORN_SEQ\n");
			struct fault *fault = &faults[fault_nr];
			lazyfs_fault *lf = &(fault->fault_details.lazyfs_fault);

			char msg[2048];
			snprintf(msg, sizeof(msg), "lazyfs::torn-seq");
			append_lazyfs_param(msg, sizeof(msg), "file", lf->file);
			append_lazyfs_param(msg, sizeof(msg), "op", lf->fs_op);
			append_lazyfs_param(msg, sizeof(msg), "persist", lf->persist);

      		FILE *file;
            file = fopen(plan->lazyfs.pipe_location, "w");

            if (file == NULL) {
                perror("Error opening file");
                break;
            }
            size_t msg_len = strlen(msg) + 1;
            ssize_t _written = write(fileno(file), msg, msg_len);
            if (_written == -1) {
                perror("write failed");
            }

            fclose(file);

            printf("  ✓ lazyfs pipe written (torn-seq): %s\n", msg);
            fault->done++;

            break;
        }
        case PARTIAL_WRITE_FAULT:{
			// rose.ko is armed synchronously, in-kernel, from within the same
			// kprobe invocation that detected the fault's conditions were met
			// (state_processor.bpf.h's inject_fault() calls rose.c's
			// bpf_rose_arm_partial_write() kfunc directly) - by the time this
			// event reaches userspace, arming has already happened. This case
			// only exists for the same bookkeeping/logging every other fault
			// type does on its ring-buffer event.
			struct fault *fault = &faults[fault_nr];
			partial_write_fault *pwf = &(fault->fault_details.partial_write_fault);
			printf("  [event]  PARTIAL_WRITE_FAULT  pid=%d  count=%d\n", e->pid, pwf->count);
			fault->done++;
			break;
        }
        case PARTIAL_READ_FAULT:{
			// Same as PARTIAL_WRITE_FAULT above: rose.ko's read_pre_handler is
			// already armed by the time this event reaches userspace.
			struct fault *fault = &faults[fault_nr];
			partial_read_fault *prf = &(fault->fault_details.partial_read_fault);
			printf("  [event]  PARTIAL_READ_FAULT  pid=%d  count=%d\n", e->pid, prf->count);
			fault->done++;
			break;
        }
        case TORN_READ_FAULT:{
			// Same as PARTIAL_WRITE_FAULT above: rose.ko's torn_read_krp
			// kretprobe is already armed by the time this event reaches
			// userspace.
			struct fault *fault = &faults[fault_nr];
			torn_read_fault *trf = &(fault->fault_details.torn_read_fault);
			printf("  [event]  TORN_READ_FAULT  pid=%d  offset=%d\n", e->pid, trf->offset);
			fault->done++;
			break;
        }
        case CRASH_FS:{
            printf("  [event]  CRASH_FS\n");
            struct fault *fault = &faults[fault_nr];
            lazyfs_fault *lf = &(fault->fault_details.lazyfs_fault);

            char msg[2048];
            snprintf(msg, sizeof(msg), "lazyfs::crash");
            append_lazyfs_param(msg, sizeof(msg), "op", lf->fs_op);
            append_lazyfs_param(msg, sizeof(msg), "from_rgx", lf->from_rgx);
            append_lazyfs_param(msg, sizeof(msg), "to_rgx", lf->to_rgx);

      		FILE *file;
            file = fopen(plan->lazyfs.pipe_location, "w");

            if (file == NULL) {
                perror("Error opening file");
                break;
            }
            size_t msg_len = strlen(msg) + 1;
            ssize_t _written = write(fileno(file), msg, msg_len);
            if (_written == -1) {
                perror("write failed");
            }

            fclose(file);

            printf("  ✓ lazyfs pipe written (crash): %s\n", msg);
            fault->done++;
            break;
        }
	}

	if(faults[fault_nr].exit){
		kill(getpid(),SIGINT);
	}
	return 1;
}

void choose_leader(){
	int one = 1;
	int zero = 0;
	for(int i=0;i < NODE_COUNT; i++){
		if (nodes[i].leader == 1){
			LEADER_PID = nodes[i].pid;
			int error = bpf_map_update_elem(constants.auxiliary_info_map_fd,&zero,&(nodes[i].pid),BPF_ANY);

			if(error){
				printf("  ✗ map update (leader pid) err=%d\n",error);
			}
			//printf("Node %s is %d \n",nodes[i].name,one);
			error = bpf_map_update_elem(constants.nodes_status_map_fd,&(nodes[i].pid),&one,BPF_ANY);
			if(error){
				printf("  ✗ map update (node_status leader) err=%d\n",error);
			}
		}else{
			//printf("Node %s is %d \n",nodes[i].name,zero);
			int error = bpf_map_update_elem(constants.nodes_status_map_fd,&(nodes[i].pid),&zero,BPF_ANY);
			if(error){
				printf("  ✗ map update (node_status) err=%d\n",error);
			}
		}
		int pos = i + 2;
		int error = bpf_map_update_elem(constants.auxiliary_info_map_fd,&pos,&(nodes[i].pid),BPF_ANY);
		if(error){
			printf("  ✗ map update (auxiliary_info) err=%d\n",error);
		}
	}
}

void restart_process(void* args){

	int duration = ((struct process_fault_args*)args)->duration;
	int node_to_restart = ((struct process_fault_args*)args)->node_to_restart;
	node *node = &nodes[node_to_restart];
	if (duration){
		sleep(duration/1000);
	}
	int current_pid_pre_restart = node->current_pid;
	int temp_pid;
	if(node->container){
		start_target_process_in_container(node_to_restart,&temp_pid);
		//retrieve_new_pid_container(node_to_restart,temp_pid);
		node->current_pid = temp_pid;
		// if (node->container_type == CONTAINER_TYPE_DOCKER){
		//     send_signal(node->current_pid,SIGSTOP,node->name);
		// }
	}
	else{
		start_target_process(node_to_restart,&temp_pid);
	}

	if (node->container && deployment_tracer){
		send_node_and_pid_to_tracer(node->container_pid,node->container_type,node->current_pid,node->name,node->if_index);
	}

	if(node->container){
		//TODO: MAKE BETTER MECHANISM
	    sleep_for_ms(10);
		send_signal(node->current_pid,SIGUSR1,node->name);
    	//For Faults we need the actual pid of the restarted process
    	retrieve_new_pid_container(node_to_restart,temp_pid);
        send_signal(node->current_pid,SIGSTOP,node->name);
    	update_node_pid_ebpf(node_to_restart,node->current_pid,node->pid,current_pid_pre_restart);
        send_signal(node->current_pid,SIGCONT,node->name);
    }
	else{
	    sleep_for_ms(10);
		send_signal(node->current_pid,SIGUSR1,node->name);
	}

}

//Gets the child of the child pid we started with popen.
//This assumes a sh script, which uses exec -a "$0" to start the node process
void retrieve_new_pid_container(int node_nr,int nsenter_pid){
	// Bounded retry with a small backoff, not an unconditional busy-spin:
	// same class of risk as collect_container_pids() (see its comment) -
	// if the expected child never appears (nsenter failed, the target
	// process died, etc.) this must not burn a full CPU core forever with
	// no way out.
	int attempts = 0;
	const int max_attempts = 300; // 300 * 10ms = 3s
	int child_pid = get_children_pids(nsenter_pid);
	while(!child_pid && attempts < max_attempts){
		usleep(10000);
		attempts++;
		child_pid = get_children_pids(nsenter_pid);
	}
	if (!child_pid) {
		fprintf(stderr, "  [retrieve_new_pid_container]  ERROR: node[%d] nsenter_pid=%d never got a child after 3s\n", node_nr, nsenter_pid);
		return;
	}
	attempts = 0;
	int script_pid = get_children_pids(child_pid);
	while(!script_pid && attempts < max_attempts){
		usleep(10000);
		attempts++;
		script_pid = get_children_pids(child_pid);
	}
	if (!script_pid) {
		fprintf(stderr, "  [retrieve_new_pid_container]  ERROR: node[%d] child_pid=%d never got its own child after 3s\n", node_nr, child_pid);
		return;
	}
	nodes[node_nr].current_pid = script_pid;
	printf("  [pid]  node[%d]  %d -> %d\n",node_nr,nsenter_pid,script_pid);

}

//new_pid is the pid of the new script
//boot_pid the pid that information is based in the maps
//old pid is the pid pre restart
void update_node_pid_ebpf(int node_nr,int new_pid,int boot_pid,int old_pid){
    printf("  [pid]  pid_tree   child=%d  parent=%d\n",new_pid,old_pid);
	printf("  [pid]  translate  new=%d  boot=%d\n",new_pid,boot_pid);

	// TEMPORARY timing instrumentation - catching a conflicting write to
	// the SAME translator key close in time (same clock source as the
	// kernel side's bpf_ktime_get_ns() - CLOCK_MONOTONIC), to confirm/
	// refute the suspected nodes_pid_translator race. Revert after
	// diagnosis.
	struct timespec dbgxlat_ts;
	clock_gettime(CLOCK_MONOTONIC, &dbgxlat_ts);
	printf("DBGXLAT: ts=%llu USERSPACE_RESTART key=%d origin=%d\n",
	       (unsigned long long)dbgxlat_ts.tv_sec * 1000000000ULL + dbgxlat_ts.tv_nsec,
	       new_pid, boot_pid);

	int one = 1;
	//Insert in the map which is a pid_tree
	int error = bpf_map_update_elem(constants.pids, &new_pid, &old_pid, BPF_ANY);
	if(error){
		printf("  ✗ map update (pids) err=%d\n",error);
	}

	//Insert in the map which maps new_pid -> boot_pid, to access faults structures
	error = bpf_map_update_elem(constants.nodes_translator_map_fd,&new_pid,&boot_pid,BPF_ANY);
	if(error){
		printf("  ✗ map update (pid_translator) err=%d\n",error);
	}

	//Insert in the map which contains node_status (checks if faults are gonna be injected)
	int zero = 0;
	error = bpf_map_update_elem(constants.nodes_status_map_fd,&new_pid,&zero,BPF_ANY);
	if(error){
		printf("  ✗ map update (node_status insert) err=%d\n",error);
	}

	error = bpf_map_delete_elem(constants.nodes_status_map_fd,&old_pid);
	if(error){
		printf("  ✗ map delete (node_status old_pid) err=%d\n",error);
	}
	//+2 is because the first two positions are reserved for other information
	int pos = node_nr + 2;
	error = bpf_map_update_elem(constants.auxiliary_info_map_fd,&pos,&new_pid,BPF_ANY);
	if(error){
		printf("  ✗ map update (auxiliary_info) err=%d\n",error);
	}

	//Updates the pid in the fault structure, so that we know in what pid the fault must be injected
    for (int i = 0; i < FAULT_COUNT; i++) {
        struct simplified_fault fault;
        int lookup_err = bpf_map_lookup_elem(constants.bpf_map_fault_fd, &i, &fault);
        if (lookup_err) {
            printf("  ✗ [pid]  fault map lookup failed  key=%d  errno=%d\n", i, lookup_err);
            continue;
        }

        if (fault.pid == old_pid) {
            fault.pid = new_pid;
            int update_err = bpf_map_update_elem(constants.bpf_map_fault_fd, &i, &fault, BPF_ANY);
            if (update_err) {
                printf("  ✗ [pid]  fault pid update failed  fault=%d  new_pid=%d  err=%d\n", i, new_pid, update_err);
            } else {
                printf("  [pid]  fault=%d  %d -> %d\n", i, old_pid, new_pid);
            }
        }
    }
}

//Reinject the uprobes after we kill a process, in theory it might not be needed due to the use of -1 and process tracking
// TODO: Test without this
void reinject_uprobes(int node_nr){
	node *node = &nodes[node_nr];
	if(node->container){
	    if(node->leader_probe){
           	char *dir;
           	if (nodes[node_nr].container_type == CONTAINER_TYPE_DOCKER)
                dir = get_docker_container_location(nodes[node_nr].name);
           	if (nodes[node_nr].container_type == CONTAINER_TYPE_LXC)
                dir = get_lxc_container_location(nodes[node_nr].name);
      		char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
      		snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, nodes->binary);
      		node->leader_probe = uprobe(nodes->current_pid,nodes->leader_symbol,combined_path,FAULT_COUNT,0,constants.mode,1,0,false);
		}
	}
	int user_func_cond_nr = 0;
	for(int i=0;i<FAULT_COUNT;i++){
		if(faults[i].traced == node_nr){
			for(int j = 0; j <faults[i].relevant_conditions;j++){
				int type = faults[i].fault_conditions_begin[j].type;
				if(type == USER_FUNCTION){
					user_function user_function = faults[i].fault_conditions_begin[j].condition.user_function;
					faults[i].fault_conditions_begin[j].condition.user_function.cond_nr = user_func_cond_nr+STATE_PROPERTIES_COUNT;
					if(node->container){
						char *dir;
						if (nodes[node_nr].container_type == CONTAINER_TYPE_DOCKER)
						   dir = get_docker_container_location(nodes[node_nr].name);
						if (nodes[node_nr].container_type == CONTAINER_TYPE_LXC)
						   dir = get_lxc_container_location(nodes[node_nr].name);
						//Combine paths
						char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
						snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, user_function.binary_location);
						faults[i].list_of_functions[user_func_cond_nr] = uprobe(node->current_pid,user_function.symbol,combined_path,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.mode,0,user_function.offset,user_function.absolute_offset);
					}else{
						faults[i].list_of_functions[user_func_cond_nr] = uprobe(node->current_pid,user_function.symbol,user_function.binary_location,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.mode,0,user_function.offset,user_function.absolute_offset);
					}
					user_func_cond_nr++;
				}
			}
		}
	}
}

int get_node_nr_from_pid(int pid){
	for(int i=0;i < NODE_COUNT; i++){
		if (nodes[i].current_pid == pid){
			return i;
		}
	}
	return -1;
}

//prints output of process we started
void print_output(void* args){
	char inLine[1024];
	FILE *fp = ((struct process_args*)args)->fp;
	int pid = *(((struct process_args*)args)->pid);
    while (fgets(inLine, sizeof(inLine), fp) != NULL)
    {
			printf("%s", inLine);
			fflush(stdout);
    }
}
