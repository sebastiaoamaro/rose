// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <bits/pthreadtypes.h>
#include <linux/bpf.h>
#include <signal.h>
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
//Modules
#include <aux.skel.h>
#include <fault_inject.h>
#include <fault_inject.skel.h>
#include <fs.h>
#include <fs.skel.h>
#include <uprobes.h>
#include <uprobes.skel.h>
#include <popen.h>
#include <fault_schedule.h>
#include <aux.h>
#include <sys/wait.h>
void process_counter(const struct event *event,int stateinfo);
int process_tc(const struct event*);
void process_fs(const struct event*);
void inject_fault(int faulttype,int pid,int fault_id,int syscall_nr);
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
static void handle_event(void *ctx,void *data,size_t data_sz);
void run_setup();
void collect_container_pids();
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

const char *argp_program_version = "Tool for FI 0.01";
const char *argp_program_bug_address = "sebastiao.amaro@ŧecnico.ulisboa.pt";
const char argp_program_doc[] = "eBPF Fault Injection Tool.\n"
				"\n"
				"USAGE: ./main/main [-f fault count] [-d network device count] [-p process ids] \n";


//TODO: remove non_used rename to maps
static struct constants {
	int faulttype_fd;
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
	int timemode;
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

struct lazyfs_args {
    int lazyfs_rb;
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
	setup_node_scripts();
	collect_container_processes();
	sleep_for_ms(500);
	setup_begin_conditions();
	if (deployment_tracer){
	    send_info_to_tracer();
	}
	choose_leader();
	setup_tc_progs();

	int err;
	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(aux_bpf->maps.rb), handle_event, NULL, NULL);

	//If they are containers we start before the workload
	write_start_event();
	start_container_nodes_scripts();
	start_lazyfs();

	pthread_t lazyfs_thread;

	if(plan->lazyfs.pid != 0){
	    int lazyfs_rb = bpf_map__fd(aux_bpf->maps.lazyfs_rb);
		struct lazyfs_args *args = (struct lazyfs_args*)malloc(sizeof(struct lazyfs_args));
		args->lazyfs_rb = lazyfs_rb;
	    pthread_create(&lazyfs_thread, NULL, (void*)start_lazyfs_handler, (void*)args);
	}

	start_nodes_scripts();
	start_pre_workload();

	//Start eBPF FI program
	add_faults_to_bpf();
	struct fault_inject_bpf* fault_inject_bpf;

	fault_inject_bpf = fault_inject(FAULT_COUNT,constants.timemode);

	if (!fault_inject_bpf){
		printf("Error in creating fault injection bpf\n");
		goto cleanup;
	}

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
			waitpid(plan->workload.pid,NULL,0);
		}
	}

	if (plan->workload.pid){
		fclose(plan->workload.read_end);
	}
	if (plan->pre_workload.pid){
		fclose(plan->pre_workload.read_end);
	}

	printf("SLEEPING: %d, BEFORE CLEANUP\n",plan->cleanup.duration);
	sleep(plan->cleanup.duration);
	printf("EXPERIMENT ENDED, RUNNING CLEANUP\n");

	if(!fault_inject_bpf)
		fault_inject_bpf__destroy(fault_inject_bpf);
	if(!aux_bpf)
		aux_bpf__destroy(aux_bpf);
	if(!rb)
		ring_buffer__free(rb);

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
				printf("Fault name is %s \n",faults[fault_nr].name);
				if (target == -2)
					fprintf(fptr,"Node:%s,Pid:0,Tid:0,event_type:Fault,event_name:%s,ret:0,time:%llu,arg1:%d,arg2:0,arg3:0,arg4:0,arg5:na\n","majority",faults[fault_nr].name,fault.timestamp,fault.fault_nr);
				if (target == -1)
					fprintf(fptr,"Node:%s,Pid:0,Tid:0,event_type:Fault,event_name:%s,ret:0,time:%llu,arg1:%d,arg2:0,arg3:0,arg4:0,arg5:na\n","leader",faults[fault_nr].name,fault.timestamp,fault.fault_nr);
				if (target >= 0)
					fprintf(fptr,"Node:%s,Pid:0,Tid:0,event_type:Fault,event_name:%s,ret:0,time:%llu,arg1:%d,arg2:0,arg3:0,arg4:0,arg5:na\n",nodes[target].name,faults[fault_nr].name,fault.timestamp,fault.fault_nr);
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

	printf("KILLING NODES and TC PROGS\n");
	for(int i =0; i< NODE_COUNT;i++){

		if(strlen(nodes[i].script)){
			kill(nodes[i].current_pid,SIGTERM);
			waitpid(nodes[i].current_pid,NULL,0);
			printf("KILLED PID: %d\n",nodes[i].current_pid);
		}

		if(nodes[i].pid_tc_in > 0){
			kill(nodes[i].pid_tc_in,SIGINT);
			waitpid(nodes[i].pid_tc_in,NULL,0);
		}
		if(nodes[i].pid_tc_out > 0){
			kill(nodes[i].pid_tc_out,SIGINT);
			waitpid(nodes[i].pid_tc_in,NULL,0);
		}
	}

	if(plan->lazyfs.script){
	    kill(plan->lazyfs.pid,SIGTERM);
	}
	printf("REAPING CHILD PROCESSES\n");
	kill_child_processes(getpid());
    kill(-getpid(), SIGTERM);
    while (waitpid(-1, NULL, WNOHANG) > 0){sleep(1);printf("Waiting for child processes\n");};
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
	sleep(1);
	send_signal(deployment_tracer->pid,SIGUSR1,"tracer");

}

void create_pipes(){
    char write_pipe[FILENAME_MAX_SIZE];
    char read_pipe[FILENAME_MAX_SIZE];

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
    printf("Created FIFO for write: %s\n", write_pipe);
    printf("Created FIFO for read: %s\n", read_pipe);
}
void open_tracer_pipe(){
	int fd;
    char write_pipe[FILENAME_MAX_SIZE];
    char read_pipe[FILENAME_MAX_SIZE];
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
	    printf("Failed to open FIFO for write: %s\n", write_pipe);
		perror("open");
		exit(EXIT_FAILURE);
	}
	deployment_tracer->pipe_write_end = fd;

	fd = open(read_pipe, O_RDONLY);
	if (fd == -1) {
	    printf("Failed to open FIFO for read: %s\n", read_pipe);
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
	constants.faulttype_fd = bpf_map__fd(bpf->maps.faults_specification	);
	constants.blocked_ips = bpf_map__fd(bpf->maps.blocked_ips);
	constants.files = bpf_map__fd(bpf->maps.files);
	constants.relevant_fd = bpf_map__fd(bpf->maps.relevant_fd);
	constants.bpf_map_fault_fd = bpf_map__fd(bpf->maps.faults);
	constants.auxiliary_info_map_fd = bpf_map__fd(bpf->maps.auxiliary_info);
	constants.nodes_status_map_fd = bpf_map__fd(bpf->maps.nodes_status);
	constants.nodes_translator_map_fd = bpf_map__fd(bpf->maps.nodes_pid_translator);
	constants.pids = bpf_map__fd(bpf->maps.pids);


};

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
		printf("Creating Setup process \n");
		FILE *fp = custom_popen(plan->setup.script,args_script,env_script,'r',&(plan->setup.pid),0);

		pthread_t thread_id;
		struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

		args->fp= fp;
		args->pid = &(plan->setup.pid);
		pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	}

	if(strlen(plan->pre_workload.script)){
		printf("Creating Pre Workload process \n");
		FILE *fp = custom_popen(plan->pre_workload.script,args_script,env_script,'r',&(plan->pre_workload.pid),0);
		plan->pre_workload.read_end = fp;
		pthread_t thread_id;
		struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

		args->fp= fp;
		args->pid = &(plan->pre_workload.pid);
		pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	}

	if(strlen(plan->workload.script)){
		printf("Creating Workload process \n");
		FILE *fp = custom_popen(plan->workload.script,args_script,env_script,'r',&(plan->workload.pid),0);
		plan->workload.read_end = fp;
		pthread_t thread_id;
		struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

		args->fp= fp;
		args->pid = &(plan->workload.pid);
		pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	}

	if(strlen(plan->lazyfs.script)){

		char *lazyfs_args_script[6];

        lazyfs_args_script[0] = plan->lazyfs.script;
        lazyfs_args_script[1] = "-f";
        lazyfs_args_script[2] = plan->lazyfs.mount_dir;
        lazyfs_args_script[3] = "-r";
        lazyfs_args_script[4] = plan->lazyfs.root_dir;
        lazyfs_args_script[5] = NULL;

    	print_block("Creating LazyFS process");
    	FILE *fp = custom_popen(plan->lazyfs.script,lazyfs_args_script,env_script,'r',&(plan->lazyfs.pid),0);
    	plan->lazyfs.read_end = fp;
    	pthread_t thread_id;
    	struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

    	args->fp= fp;
    	args->pid = &(plan->lazyfs.pid);
    	pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	}
	//Start setup
	if(strlen(plan->setup.script)){
		sleep(1);
    	kill(plan->setup.pid,SIGUSR1);
	}
	//Sleep while we wait for setup to start
	if(plan->setup.duration > 0){
	   printf("WAITING FOR SETUP TO START \n");
	   sleep(plan->setup.duration);
	}
}

void start_workload(){
	//Start workload
		if (!plan)
			return;
		if(plan->workload.pid == 0)
			return;
		printf("Started workload from execution plan with pid %d \n",plan->workload.pid);
		kill(plan->workload.pid,SIGUSR1);
}


void start_pre_workload(){
	//Start workload
	if (!plan)
		return;
	if(plan->pre_workload.pid == 0)
		return;
	printf("Started pre_workload from execution plan with pid %d \n",plan->pre_workload.pid);
	kill(plan->pre_workload.pid,SIGUSR1);

    int status;

    printf("Waiting for pre_workload %d to terminate...\n", plan->pre_workload.pid);

    if (waitpid(plan->pre_workload.pid, &status, 0) == -1) {
            perror("waitpid failed");
        } else {
            if (WIFEXITED(status)) {
                printf("Process %d exited with status %d\n", plan->pre_workload.pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("Process %d was terminated by signal %d\n", plan->pre_workload.pid, WTERMSIG(status));
            } else {
                printf("Process %d ended (unknown reason)\n", plan->pre_workload.pid);
            }
        }
}
//Starts the lazy_fs process in the background
void start_lazyfs(){
	//Start workload
	if (!plan)
		return;
	if(plan->lazyfs.pid == 0)
		return;

	printf("Started lazyfs from execution plan with pid %d \n",plan->lazyfs.pid);
	kill(plan->lazyfs.pid,SIGUSR1);
}

//TODO: Collect container pids, waits until they start
void collect_container_pids(){
	int node_count = 0;
	while (node_count != NODE_COUNT){
		node_count = 0;
		for(int i=0; i < NODE_COUNT;i++){
			if (nodes[i].container){
			    int container_pid = 0;
				if (nodes[i].container_type == CONTAINER_TYPE_DOCKER){
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
	}

}

void setup_node_scripts(){
	for(int i=0;i<NODE_COUNT;i++){
		if(!nodes[i].script[0]){
			//printf("No command in this node %d \n",i);
			continue;
		}
		if (!strlen(nodes[i].script)){
			printf("Empty command \n");
			continue;
		}

		if (nodes[i].container){
		    if (!strlen(nodes[i].pid_file)){
				printf("Starting processes with command %s \n",nodes[i].script);
				start_target_process_in_container(i,&nodes[i].pid);
			}
		}
		else if (!nodes[i].container){
			start_target_process(i,&nodes[i].pid);
			printf("Node %d with pid %d \n",i,nodes[i].pid);
			nodes[i].current_pid = nodes[i].pid;
			int one = 1;
			bpf_map_update_elem(constants.pids, &nodes[i].current_pid, &one, BPF_ANY);
		}
	}
}

void collect_container_processes(){
    printf("Collecting container processes \n");
	for(int i = 0; i< NODE_COUNT; i++){
		if (nodes[i].container && strlen(nodes[i].script) > 0 && !(strlen(nodes[i].pid_file))){
			printf("WAITING FOR PID \n");
			int child_pid = get_children_pids(nodes[i].pid);

			while(!child_pid){
				sleep(1);
				child_pid = get_children_pids(nodes[i].pid);
			}
			int script_pid = get_children_pids(child_pid);

			while(!script_pid){
				sleep(1);
				script_pid = get_children_pids(child_pid);
			}
			nodes[i].pid = script_pid;
			nodes[i].current_pid = script_pid;
			send_signal(script_pid,SIGSTOP,nodes[i].name);
			int one = 1;
			bpf_map_update_elem(constants.pids, &nodes[i].current_pid, &one, BPF_ANY);
		}
		if (nodes[i].container){
          	 if (strlen(nodes[i].pid_file)){
                printf("LOOKING FOR PID IN FILE %s\n",nodes[i].pid_file);
                char *dir;
                if (nodes[i].container_type == CONTAINER_TYPE_DOCKER){
                    dir = get_docker_container_location(nodes[i].name);
                }
                if (nodes[i].container_type == CONTAINER_TYPE_LXC){
                    dir = get_lxc_container_location(nodes[i].name);
                }

                char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
                snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, nodes[i].pid_file);

                printf("Combined path %s\n", combined_path);
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
                    printf("PID IN FILE IS: %d \n", pid);
                } else {
                    printf("Failed to read an integer.\n");
                }

                int host_pid = find_host_pid_for_container_pid(pid);
                printf("HOST PID IS %d\n",host_pid);
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

		//Here we wait until tracer created the structs until we proceed
        char buffer[8];
        ssize_t bytesRead = read(deployment_tracer->pipe_read_end, buffer, sizeof(buffer) - 1);
        if (bytesRead == -1) {
            perror("read");
            close(deployment_tracer->pipe_read_end);
            exit(EXIT_FAILURE);
        }
    printf("ROSE->TRACER: %s\n", message);
}

void start_nodes_scripts(){
    printf("NODES: STARTED\n");
	for(int i=0;i<NODE_COUNT;i++){
		if (!(nodes[i].container)){
			kill(nodes[i].pid,SIGUSR1);
		}
	}
}
void start_container_nodes_scripts(){
	print_block("CONTAINER SCRIPTS: STARTED");
	for(int i=0;i<NODE_COUNT;i++){
		if (nodes[i].container){
			kill(nodes[i].pid,SIGCONT);
		}
		if(nodes[i].pid_tc_in !=0){
			kill(nodes[i].pid_tc_in,SIGUSR1);
		}
		if(nodes[i].pid_tc_out !=0){
			kill(nodes[i].pid_tc_out,SIGUSR1);
		}
	}
}

FILE* start_target_process(int node_number, int *pid){

	printf("Starting target script for node:%s with script:%s\n",nodes[node_number].name,nodes[node_number].script);

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
	char *token_env = strtok(nodes[node_number].env," ");
	env_script[0]=(char*)malloc(STRING_SIZE*sizeof(char));

	int pos_env = 1;

	if(token_env != NULL){
		strcpy(env_script[0],token_env);
		pos_env = 0;
	}

	token_env = strtok(NULL," ");

	while(token_env != NULL ) {
		env_script[pos_env]=(char*)malloc(STRING_SIZE*sizeof(char));
		strcpy(env_script[pos_env],token_env);

		//printf("Added %s to env of %s",env_script[pos_env],nodes[node_number].name);

		token_env = strtok(NULL," ");
		pos_env++;
   	}
   	env_script[pos_env]= NULL;

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
    	nsenter_args[9] = token;

    	index = 9;
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
	char *token_env = strtok(nodes[node_number].env," ");
	env_script[0]=(char*)malloc(STRING_SIZE*sizeof(char));

	int pos_env = 1;
	if(token_env != NULL){
		strcpy(env_script[0],token_env);
		pos_env = 0;
	}
	token_env = strtok(NULL," ");
	while(token_env != NULL ) {
		env_script[pos_env]=(char*)malloc(STRING_SIZE*sizeof(char));
		strcpy(env_script[pos_env],token_env);
		token_env = strtok(NULL," ");
		pos_env++;
   	}
   	env_script[pos_env]= NULL;

	FILE *fp;
	if(nodes[node_number].running)
		fp = custom_popen("nsenter",nodes[node_number].args,env_script,'r',pid,1);
	else{
		fp = custom_popen("nsenter",nsenter_args,env_script,'r',pid,1);
		nodes[node_number].running = 1;
		nodes[node_number].args = nsenter_args;
	}
	if (!fp)
    {
        perror("popen failed:");
        exit(1);
    }

	printf("STARTED NODE %s,NS_PID:%d,PID:%d,SCRIPT:%s\n",nodes[node_number].name,nodes[node_number].container_pid,*pid,nodes[node_number].script);
	pthread_t thread_id;
	struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));
	args->fp= fp;
	args->pid = pid;
	pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);
	return fp;
}


void setup_begin_conditions(){

	print_block("Adding relevant conditions, file_names and uprobes to kernel");
	int user_func_cond_nr = 0;
	for(int i = 0; i < FAULT_COUNT; i++){
		int has_time_condition = 0;
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
					printf("Created fileinfo with filename %s and len %d\n",file_info.filename,file_info.size);
				}

				int syscall_nr = syscall.syscall;

				struct info_key info_key = {
					pid,
					syscall_nr
				};

				error = bpf_map_update_elem(constants.files,&info_key,&file_info,BPF_ANY);
				if (error){
					printf("Error of update in files_opened is %d, value->%s \n",error,file_info.filename);
				}

				struct relevant_fds relevant_fd_init = {};

				error = bpf_map_update_elem(constants.relevant_fd,&pid,&relevant_fd_init,BPF_ANY);
				if (error){
					printf("Error of update in files_opened is %d, value->%d \n",error,pid);
				}

				insert_relevant_condition_in_ebpf(i,pid,syscall_nr,syscall.call_count);

			}
			if(type == USER_FUNCTION){
				//user_func_cond_nr is the position where the call_count will reside in fault_type_conditions
				user_function user_function = faults[i].fault_conditions_begin[j].condition.user_function;
				faults[i].fault_conditions_begin[j].condition.user_function.cond_nr = user_func_cond_nr+STATE_PROPERTIES_COUNT;

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

					faults[i].list_of_functions[user_func_cond_nr] = uprobe(pid,user_function.symbol,combined_path,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.timemode,0,user_function.offset);
				}else{
					faults[i].list_of_functions[user_func_cond_nr] = uprobe(pid,user_function.symbol,user_function.binary_location,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.timemode,0,user_function.offset);
				}
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
		}
		//printf("has_time_condition %d and relevant conditions %d \n",has_time_condition,faults[i].relevant_conditions);
		if (has_time_condition){
			//printf("Need to process all syscalls to check time \n");
			constants.timemode = 1;
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
					nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,combined_path,FAULT_COUNT,0,constants.timemode, 1,0);
				}else{
					nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,nodes[i].leader_symbol,FAULT_COUNT,0,constants.timemode, 1,0);
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
					nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,combined_path,FAULT_COUNT,0,constants.timemode, 1,0);

				}else{
					nodes[i].leader_probe = uprobe(nodes[i].pid,nodes[i].leader_symbol,nodes[i].binary,FAULT_COUNT,0,constants.timemode, 1,0);
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

	printf("FAULT %d state info pos[%d] is %d conditions match is [%d] with pid %d \n",fault_nr,cond_nr,new_information_state->relevant_states[fault_nr],faults[fault_nr].initial.conditions_match[fault_nr],pid);
	struct info_state *old_information_state = (struct info_state*)malloc(sizeof(struct info_state));

	old_information_state->current_value = 0;

	int exists = 0;
	exists = bpf_map_lookup_or_try_init_user(constants.relevant_state_info_fd,&information,new_information_state,old_information_state);

	//if already exists add
	if(exists){
		old_information_state->relevant_states[fault_nr] = call_count;
		error = bpf_map_update_elem(constants.relevant_state_info_fd,&information,old_information_state,BPF_ANY);
		if (error){
			printf("Error of update is %d, key->%d \n",error,cond_nr);
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
		printf("ROSE: ADDING FAULT TO BPF NR: %d, TYPE:%d, PID:%d \n",i,faults[i].faulttype,nodes[faults[i].traced].pid);
		struct simplified_fault new_fault;
		new_fault.run = 0;
		new_fault.duration = faults[i].duration;
		new_fault.start_time = 0;
		new_fault.timestamp = 0;
		new_fault.faulttype = faults[i].faulttype;
		new_fault.done = faults[i].done;
		new_fault.quorum_size = QUORUM;
		new_fault.faults_done = 0;
		new_fault.pid = nodes[faults[i].traced].pid;

		new_fault.target = faults[i].target;

		if (faults[i].faulttype == BLOCK_IPS)
		  new_fault.target_if_index = get_interface_index(nodes[faults[i].target].veth)-1;
		new_fault.occurrences = faults[i].occurrences;
		new_fault.relevant_conditions = faults[i].relevant_conditions;
		new_fault.fault_nr = i;
		new_fault.repeat = faults[i].repeat;

		for(int k = 0; k < (STATE_PROPERTIES_COUNT+MAX_FUNCTIONS); k++){
			new_fault.initial.conditions_match[k] = 0;
			new_fault.initial.fault_type_conditions[k] = 0;
		}

		for(int j = 0; j <faults[i].relevant_conditions;j++){
			int type = faults[i].fault_conditions_begin[j].type;
			if(type == SYSCALL){
				system_call syscall = faults[i].fault_conditions_begin[j].condition.syscall;
				int cond_nr = syscall.syscall;
				new_fault.initial.fault_type_conditions[cond_nr] = syscall.call_count;
				printf("Fault %d has condition system call %d with call_count %d \n",i,cond_nr,syscall.call_count);
			}
			if (type == FILE_SYSCALL){
				file_system_call syscall = faults[i].fault_conditions_begin[j].condition.file_system_call;
				int cond_nr = syscall.syscall;
				new_fault.initial.fault_type_conditions[cond_nr] = syscall.call_count;
				printf("Fault %d has condition file_system_call %d with call_count %d \n",i,cond_nr,syscall.call_count);
			}
			if(type == USER_FUNCTION){
				user_function user_function = faults[i].fault_conditions_begin[j].condition.user_function;
				int cond_nr = user_function.cond_nr;
				new_fault.initial.fault_type_conditions[cond_nr] = user_function.call_count;
				printf("Fault %d has condition user_function name: %s id:%d with call_count %d \n",i,user_function.symbol,cond_nr,user_function.call_count);
			}
			if(type == TIME){
				new_fault.initial.fault_type_conditions[TIME_STATE] = faults[i].fault_conditions_begin[j].condition.time;
				printf("Fault %d has condition time %d with time %d \n",i,TIME_STATE,faults[i].fault_conditions_begin[j].condition.time);
			}
		}

		if (faults[i].category == SYSCALL_FAULT){
			new_fault.return_value = faults[i].fault_details.syscall.return_value;
		}
		if(faults[i].category == FILE_SYS_OP){

			int error;
			int pid = nodes[faults[i].traced].pid;

			file_system_operation file_system_op;

			file_system_op = faults[i].fault_details.file_system_op;

			int syscall_nr = file_system_op.syscall_condition;

			struct file_info_simple file_info = {};
			if (strlen(file_system_op.file_name)){
				//memset(file_info.filename,'\0',sizeof(file_system_op.file_name));
				strcpy(file_info.filename,file_system_op.file_name);
				file_info.size = strlen(file_info.filename);
				printf("Created fileinfo with filename %s with size %d for cond %d\n",file_info.filename,file_info.size,syscall_nr);
			}


			struct info_key info_key = {
				pid,
				syscall_nr
			};

			//Add name of file to eBPF
			error = bpf_map_update_elem(constants.files,&info_key,&file_info,BPF_ANY);
			if (error){
				printf("Error of update in files_opened is %d, value->%s \n",error,file_info.filename);
			}

			//Init relevant fd struct for this pid
			struct relevant_fds relevant_fd_init = {};

			relevant_fd_init.size = 0;

			error = bpf_map_update_elem(constants.relevant_fd,&pid,&relevant_fd_init,BPF_ANY);
			if (error){
				printf("Error of update in files_opened is %d, value->%d \n",error,pid);
			}

			new_fault.return_value = file_system_op.return_value;
		}

		//TODO GO OVER FAULT DETAILS

		int error = bpf_map_update_elem(constants.bpf_map_fault_fd,&i,&new_fault,BPF_ANY);
		if (error)
			printf("Error of update in adding fault to bpf is %d \n",error);
	}

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
	strcpy(nsenter_args[4],"./tcmain/network");
	nsenter_args[10] = NULL;

	char *env_script[STRING_SIZE];

	env_script[0] = NULL;

	for (int i =0;i<FAULT_COUNT;i++){

		if(faults[i].faulttype == BLOCK_IPS){

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
			    if (nodes[target].container_type == CONTAINER_TYPE_DOCKER){
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
				printf("Error of update in blocked_ips is %d, key->%d \n",error,index);
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
			pthread_create(&thread_id, NULL, (void *)print_output, (void*)args);

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
				printf("Error of update in blocked_ips is %d, key->%d \n",error,index);
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
		if (faults[i].faulttype == NETWORK_ISOLATION){
		}
		if(faults[i].faulttype == DROP_PACKETS){

		}



	}
	return 0;
}

void count_time(){

    int time=0;
	int maximum_time = 1000 * get_maximum_time();
	printf("COUNT_TIME: STARTED %d \n",maximum_time);
	while(1){
		sleep_for_ms(10);
		time += 10;

		for (int i = 0; i< FAULT_COUNT;i++){
			int fault_time = faults[i].initial.fault_type_conditions[TIME_STATE];
			if (time >= fault_time && faults[i].initial.fault_type_conditions[TIME_STATE]){

				struct simplified_fault fault;
				int err_lookup;
				err_lookup = bpf_map_lookup_elem(constants.bpf_map_fault_fd, &i,&fault);
				if (err_lookup){
					printf("Did not find elem in count_time errno is %d \n",errno);
				}

				if (fault.done){
					continue;
				}
				if (fault.initial.conditions_match[TIME_STATE] > 0){
					continue;
				}
				//printf("Time value property is %d \n",fault.initial.conditions_match[TIME_STATE]);
				printf("TIME:TRUE, FAULT:%d \n",fault.fault_nr);
				fault.initial.conditions_match[TIME_STATE] = 1;
				fault.run+=1;
				int error = bpf_map_update_elem(constants.bpf_map_fault_fd,&i,&fault,BPF_ANY);
				if(error)
					printf("Error of update in adding fault to bpf is %d \n",error);

			}
		}
		//Check if faults are done
		int err_lookup;
		int done_count = 0;
		for (int i = 0; i< FAULT_COUNT;i++){
			struct simplified_fault fault;
     			err_lookup = bpf_map_lookup_elem(constants.bpf_map_fault_fd, &i,&fault);
			if(err_lookup){
				printf("DID NOT FIND FAULT IN EBPF MAP, ERROR: %d \n",errno);
			}

			if (fault.done){
				done_count++;
			}
		}

		if (done_count != 0 && done_count == FAULT_COUNT){
			printf("ROSE: FAULTS DONE \n");
			exiting = true;
			break;
		}


		if (time >= maximum_time){
			printf("ROSE: MAXIMUM TIME REACHED \n");
			exiting = true;
			break;
		}

	}

}

//handles events received from the ringbuffer dedicated to lazyfs faults
void start_lazyfs_handler(void* args){
   	struct ring_buffer *rb = NULL;
    int lazyfs_rb = ((struct lazyfs_args*)args)->lazyfs_rb;
	rb = ring_buffer__new(lazyfs_rb, handle_lazyfs_events, NULL, NULL);
	int err;
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

}

//Handles events received from the lazyfs ringbuffer (eBPF)
void handle_lazyfs_events(void *ctx,void *data,size_t data_sz){
    (void)ctx;
	(void)data_sz;

	const struct event *e = data;

	int fault_nr = e->fault_nr;
	switch(e->type){
	    case TORN_SEQ:
			break;
	}
}

//Handles events received from ringbuffer (eBPF)
void handle_event(void *ctx,void *data,size_t data_sz)
{
	(void)ctx;
	(void)data_sz;

	const struct event *e = data;

	int fault_nr = e->fault_nr;
	switch(e->type){
		case PROCESS_STOP: {
			printf("Will stop process with target_pid %d \n",e->pid);
			pthread_t thread_id;
			struct process_fault_args *args = (struct process_fault_args*)malloc(sizeof(struct process_fault_args));

			struct fault *fault = &faults[fault_nr];

			if (fault->target == -2 && fault->done == QUORUM){
				return;
			}

			if (fault->target == -1){
				printf("Stopping LEADER %d \n ",LEADER_PID);
				args->pid = LEADER_PID;
			}else{
				args->pid = e->pid;
			}

			args->duration = fault->duration;
			args->name = nodes[get_node_nr_from_pid(args->pid)].name;

			pthread_create(&thread_id, NULL, (void*)pause_process, (void*)args);
			fault->done++;
			printf("Fault %d done %d \n",fault_nr,fault->done);

			break;
		}
		case PROCESS_KILL:{

			pthread_t thread_id;
			struct process_fault_args *args = (struct process_fault_args*)malloc(sizeof(struct process_fault_args));
			struct fault *fault = &faults[fault_nr];

			if (fault->target == -2 && fault->done == QUORUM){
				return;
			}

			if (fault->target == -1){
				printf("Stopping LEADER %d \n ",LEADER_PID);
				args->pid = LEADER_PID;
			}else{
				args->pid = e->pid;
			}


			int node_nr = get_node_nr_from_pid(e->pid);

			args->duration = fault->duration;
			args->node_to_restart = node_nr;

			printf("NODE: %s, PID: %d, DURATION: %d, FAULT_NR: %d \n",nodes[(args->node_to_restart)].name,(args->pid),(args->duration),fault_nr);

			pthread_create(&thread_id, NULL, (void*)restart_process, (void*)args);
			fault->done++;
			break;
		}
		break;
		case LEADER_CHANGE:{
			LEADER_PID = e->pid;
			printf("NEW LEADER: %d \n",e->pid);
			int zero = 0;
			int error = bpf_map_update_elem(constants.auxiliary_info_map_fd,&zero,&LEADER_PID,BPF_ANY);
			if (error){
				printf("UPDATING LEADER, ERROR: %d \n",error);
			}
			break;
		}
	}

	if(faults[fault_nr].exit){
		kill(getpid(),SIGINT);
	}
}

void choose_leader(){
	int one = 1;
	int zero = 0;
	for(int i=0;i < NODE_COUNT; i++){
		if (nodes[i].leader == 1){
			LEADER_PID = nodes[i].pid;
			int error = bpf_map_update_elem(constants.auxiliary_info_map_fd,&zero,&(nodes[i].pid),BPF_ANY);

			if(error){
				printf("Error in changing leader %d \n",error);
			}

			//printf("Node %s is %d \n",nodes[i].name,one);

			error = bpf_map_update_elem(constants.nodes_status_map_fd,&(nodes[i].pid),&one,BPF_ANY);
			if(error){
				printf("Error in updating node status for leader %d \n",error);
			}
		}else{
			//printf("Node %s is %d \n",nodes[i].name,zero);

			int error = bpf_map_update_elem(constants.nodes_status_map_fd,&(nodes[i].pid),&zero,BPF_ANY);
			if(error){
				printf("Error in updating a node %d \n",error);
			}

		}

		int pos = i + 2;
		int error = bpf_map_update_elem(constants.auxiliary_info_map_fd,&pos,&(nodes[i].pid),BPF_ANY);
		if(error){
			printf("Error in adding pid to auxiliary_info %d \n",error);
		}

	}

}

void restart_process(void* args){

	int duration = ((struct process_fault_args*)args)->duration;
	int node_to_restart = ((struct process_fault_args*)args)->node_to_restart;
	node *node = &nodes[node_to_restart];
	if (duration){
		printf("SLEEPING FOR  %d BEFORE START \n",duration/1000);
		sleep(duration/1000);
	}
	int current_pid_pre_restart = node->current_pid;
	int temp_pid;
	printf("STARTING NODE %s \n",node->name);
	if(node->container){
		start_target_process_in_container(node_to_restart,&temp_pid);
		retrieve_new_pid_container(node_to_restart,temp_pid);
		node->current_pid = temp_pid;
		if (node->container_type == CONTAINER_TYPE_DOCKER){
		    send_signal(node->current_pid,SIGSTOP,node->name);
		}
	}
	else{
		start_target_process(node_to_restart,&temp_pid);
	}
	update_node_pid_ebpf(node_to_restart,node->current_pid,node->pid,current_pid_pre_restart);
	reinject_uprobes(node_to_restart);
	if (node->container && deployment_tracer){
		send_node_and_pid_to_tracer(node->container_pid,node->container_type,node->current_pid,node->name,node->if_index);
	}
	if((node->container) && (node->container_type == CONTAINER_TYPE_DOCKER))
		send_signal(node->current_pid,SIGCONT,node->name);
	else if (!node->container){
		send_signal(node->current_pid,SIGUSR1,node->name);
	}
}

void retrieve_new_pid_container(int node_nr,int nsenter_pid){
	int child_pid = get_children_pids(nsenter_pid);
	while(!child_pid){
		child_pid = get_children_pids(nsenter_pid);
	}

	int script_pid = get_children_pids(child_pid);
	while(!script_pid){
		script_pid = get_children_pids(child_pid);
	}
	nodes[node_nr].current_pid = script_pid;

}

//new_pid is the pid of the new script
//boot_pid the pid that information is based in the maps
//old pid is the pid pre restart
void update_node_pid_ebpf(int node_nr,int new_pid,int boot_pid,int old_pid){
	printf("PID TRANSLATED: NEW: %d, OLD: %d\n",new_pid,boot_pid);
	int error = bpf_map_update_elem(constants.nodes_translator_map_fd,&new_pid,&boot_pid,BPF_ANY);
	if(error){
		printf("Error inserting in pid translator %d \n",error);
	}

	int zero = 0;
	error = bpf_map_update_elem(constants.nodes_status_map_fd,&new_pid,&zero,BPF_ANY);
	if(error){
		printf("Error inserting in node_status %d \n",error);
	}


	error = bpf_map_delete_elem(constants.nodes_status_map_fd,&old_pid);
	if(error){
		printf("Error deleting pid in node_status %d \n",error);
	}
	//+2 is because the first two positions are reserved for other information
	int pos = node_nr + 2;
	error = bpf_map_update_elem(constants.auxiliary_info_map_fd,&pos,&new_pid,BPF_ANY);
	if(error){
		printf("Error in adding pid to auxiliary_info %d \n",error);
	}
}

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
      		node->leader_probe = uprobe(nodes->current_pid,nodes->leader_symbol,combined_path,FAULT_COUNT,0,constants.timemode,1,0);
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
						faults[i].list_of_functions[user_func_cond_nr] = uprobe(node->current_pid,user_function.symbol,combined_path,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.timemode,0,user_function.offset);
					}else{
						faults[i].list_of_functions[user_func_cond_nr] = uprobe(node->current_pid,user_function.symbol,user_function.binary_location,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.timemode,0,user_function.offset);
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
	return 0;
}

//prints output of process we started
void print_output(void* args){
	char inLine[1024];
	FILE *fp = ((struct process_args*)args)->fp;

    while (fgets(inLine, sizeof(inLine), fp) != NULL)
    {
			printf("%s", inLine);
			fflush(stdout);
    }
}
