// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
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

//Modules
#include <aux.skel.h>
#include <process.h>
#include <process.skel.h>
#include <faultinject.h>
#include <faultinject.skel.h>
#include <tc.h>
#include <tc.skel.h>
#include <fs.h>
#include <fs.skel.h>
#include <block.h>
#include <block.skel.h>
#include <uprobes.h>
#include <uprobes.skel.h>
#include <popen.h>
#include <faultschedule.h>
#include <aux.h>

void process_counter(const struct event *event,int stateinfo);
int process_tc(const struct event*);
void process_fs(const struct event*);
void inject_fault(int faulttype,int pid,int fault_id,int syscall_nr);
void setup_begin_conditions();
void setup_node_scripts();
void start_node_scripts();
FILE* start_target_process(int node_number);
int setup_tc_progs(struct tc_bpf **tc_ebpf_progs);
void insert_relevant_condition_in_ebpf(int fault_nr,int pid,int cond_nr,int call_count);

const char *argp_program_version = "Tool for FI 0.01";
const char *argp_program_bug_address = "sebastiao.amaro@ŧecnico.ulisboa.pt";
const char argp_program_doc[] = "eBPF Fault Injection Tool.\n"
				"\n"
				"USAGE: ./main/main [-f fault count] [-d network device count] [-p process ids] \n";

static const struct argp_option opts[] = {
	{ "faultcount", 'f', "FAULTCOUNT", 0, "Number of faults" },
	{ "devicecount", 'd', "DEVICECOUNT", 0, "Number of network devices" },
	{ "processid", 'p', "PID", 0, "Process ID" },
	{ "inputfile", 'i', "inputfilename",0,"File with auxiliary fault information. "},
	{ "uprobes only",'u',0,0,"With this flag only uprobes will run"},
	{ "tracing only",'t',0,0,"With this flag no fault will be processed"},
	{ "maintain pid",'m',0,0,"With this flag the PID for fault 0 is used for all the other faults (no input file only flag)"},
	{ "verbose",'v',0,0,"With this flag extra information is shown in stdout"},
	{ "time",'T',0,0,"With this flag the tool will always check time"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static struct constants {
	int verbose;
	long min_duration_ms;
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
	int time;
	int time_map_fd;
	int timemode;

} constants;

struct process_args {
	int *pid;
	FILE* fp;
};

static fault* faults;
static node* nodes;
static int FAULT_COUNT = 0;
static int DEVICE_COUNT = 0;
static int NODE_COUNT = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !constants.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
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

//Stuff to properly exit
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
	printf("Main Finished \n");
} 

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case 'f':
			FAULT_COUNT = strtol(arg,NULL,10);
			faults = (struct fault*)malloc(FAULT_COUNT*sizeof(struct fault));
			break;
		case 'd':
			DEVICE_COUNT = strtol(arg,NULL,10);
			break;
		case 'p':
			constants.pid = strtol(arg,NULL,10);
			break;
		case 'i':
			constants.inputfilename = (char *)malloc(sizeof(char)*strlen(arg));
			strcpy(constants.inputfilename,arg);
			break;
		case 'u':
			constants.uprobemode = 1;
			break;
		case 't':
			constants.tracingmode = 1;
			break;
		case 'v':
			constants.faultsverbose = 1;
			break;
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		case 'm':
			constants.maintainpid = 1;
			break;
		case ARGP_KEY_END:
			if (state->argc < 2)
				/* Not enough arguments. */
				argp_usage (state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,	
	.doc = argp_program_doc,
};


//Handles events received from ringbuf (eBPF)
//TODO refactor this part of the code no longer usefull, except to process the crashing of processes
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	int fault_nr = e->fault_nr;
	struct fault *fault = &faults[fault_nr];

	int pid = nodes[fault->target].pid;
	switch(e->type){
		case PROCESS_STOP:
			
			pthread_t thread_id;

			struct process_pause_args *args = (struct process_pause_args*)malloc(sizeof(struct process_pause_args));
			
			args->duration= &fault->duration;
			args->pid = &pid;

			pthread_create(&thread_id, NULL, pause_process, (void*)args);

			fault->done = 1;
			break;
	}
	return 0;
}


//Handles network TC events
int process_tc(const struct event *event){

	char ifname[IF_NAMESIZE];

	if (event->ip_proto < 0 || event->ip_proto >= IPPROTO_MAX)
		return 0;

	if (!if_indextoname(event->ifindex, ifname))
		return 0;

	return 0;
}


//Temporary way of creating faults
void build_faults(){

	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

	for(int i = 0; i < 0;i++){
		int repeat = 0;
		int occurrences = 1;
		int network_directions = 2;
		int return_value = 0;
		int duration = 0;

		// char *binary_location = "/home/sebastiaoamaro/phd/tendermint/build/tendermint";
		// char *args[] = {"/home/sebastiaoamaro/phd/tendermint/build/tendermint","init",NULL};
		char *binary_location;
		//char args[4][64];
		// char *args[] = {"/home/sebastiaoamaro/phd/tendermint/build/tendermint","node","--proxy_app=kvstore",NULL};
		build_fault(&faults[i],repeat,TEMP_EMPTY,occurrences,duration,network_directions,return_value,NULL,0,binary_location);

		// faults[i].initial.fault_type_conditions[WRITES] = 1;
		// faults[i].initial->fault_type_conditions[PROCESS_TO_KILL] = 225183;
	
		// char string_ips[32] = "172.19.0.2";

		// add_ip_to_block(&faults[0],string_ips,0);

		// char file_name[FILENAME_MAX] = ".tendermint/";

		// strcpy(faults[i].file_open,file_name);

		//char func_names[MAX_FUNCTIONS][FUNCNAME_MAX] = {":_ZN13FullCompactor12CompactFilesEPv"};
		//char func_names[MAX_FUNCTIONS][FUNCNAME_MAX] = {":github.com/cometbft/cometbft/statesync.(*syncer).Sync"};
		//char func_names[MAX_FUNCTIONS][FUNCNAME_MAX] = {":github.com/tendermint/tendermint/libs/os.EnsureDir"};
		//add_function_to_monitor(&faults[i],&func_names[0],0);
		//add_function_to_monitor(&faults[i],&func_names[1],1);

	}
	//FAULT 0
	// char *binary_location = "/home/sebastiaoamaro/phd/tendermint/build/tendermint";
	// char *args[] = {"/home/sebastiaoamaro/phd/tendermint/build/tendermint","node","--proxy_app=kvstore",NULL};
	// int network_directions = 2;
	// int occurrences = 1;
	// int repeat = 0;
	// int return_value = -20;
	// build_fault(&faults[0],repeat,NEWFSTATAT,occurrences,network_directions,return_value,args,0,binary_location);

	//faults[0].initial.fault_type_conditions[CALLCOUNT] = 1;
	//faults[0].initial.fault_type_conditions[NEWFSTATAT_COUNT] = 1;
	//faults[0].initial.fault_type_conditions[NEW_FSTATAT_SPECIFIC] = 1;
	// faults[0].initial.fault_type_conditions[TIME_FAULT] = 5;
	
	

	// char file_name[FILENAME_MAX] = "/root/.tendermint/data";

	// strcpy(faults[0].file_open,file_name);

	//TODO:This is causing overflows fix!!!
	// char *func_names[] = {":github.com/tendermint/tendermint/libs/os.EnsureDir",NULL};
	// add_function_to_monitor(&faults[0],func_names[0],0);

	//FAULT 1

	// char *binary_location2 = "";
	// char *args2[] = {""};

	// build_fault(&faults[1],1,OPENAT,1,2,-2,args2,0,binary_location2);
	
	// strcpy(faults[1].file_open,file_name);
	// faults[1].initial.fault_type_conditions[CALLCOUNT] = 3;
	// faults[1].initial.fault_type_conditions[OPENAT_SPECIFIC] = 1;


	//FAULT 0
	char *binary_location = "";
	//char *args[] = {"/usr/bin/docker","exec", "-dit","redpanda0","ping","google.pt",NULL};
	//char *args[] = {"/usr/bin/nsenter", "-t", "82112", "-i", "-u", "-m", "-n", "-p", "-r", "./test.sh",NULL};
	char *args[] = {""};
	int network_directions = 0;
	int occurrences = 0;
	int repeat = 0;
	int return_value = 0;
	int duration = 5;
	build_fault(&faults[0],repeat,PROCESS_STOP,occurrences,duration,network_directions,return_value,args,0,binary_location);


	//char ip1[32] = "172.19.1.10";
	//char ip2[32] = "172.19.1.11";

	//add_ip_to_block(&faults[0],ip1,0);
	//add_ip_to_block(&faults[0],ip2,1);


	//faults[0].initial.fault_type_conditions[WRITES] = 1;
	faults[0].initial.fault_type_conditions[TIME_FAULT] = 5;


	//GET PIDS AND NETDEVICES from a file
	printf("Checking input file \n");
	int fault_count = 0;
	int checkfile = 1;
	fp = fopen(constants.inputfilename, "r");
    if (fp == NULL){
		//printf("Input file not found \n");
        //exit(EXIT_FAILURE);
		checkfile = 0;
	}
	if (checkfile){
		printf("Checking input file \n");
		for(int i =0; i<FAULT_COUNT;i++){

			getline(&line, &len, fp);
			//printf("Line is %s \n", line);

			int pid;

			char* token = strtok(line,";");

			pid = atoi(token);

			faults[fault_count].pid = pid;

			token = strtok(NULL,"");

			if (token){
				strtok(token,"\n");
				if(strlen(token) !=1 ){
					printf("newline is %s and len is %ld \n",token,strlen(token));
					set_if_name(&faults[fault_count],token);
				}else{
					set_if_name(&faults[fault_count],"\0");
				}
			}else{
				set_if_name(&faults[fault_count],"\0");
			}

			fault_count++;

		}

	}
	
}

//Save FD of maps in constants
void get_fd_of_maps (struct aux_bpf *bpf){
	constants.relevant_state_info_fd = bpf_map__fd(bpf->maps.relevant_state_info);
	constants.faulttype_fd = bpf_map__fd(bpf->maps.faults_specification	);
	constants.blocked_ips = bpf_map__fd(bpf->maps.blocked_ips);
	constants.files = bpf_map__fd(bpf->maps.files);
	constants.relevant_fd = bpf_map__fd(bpf->maps.relevant_fd);
	constants.bpf_map_fault_fd = bpf_map__fd(bpf->maps.faults);
	constants.time_map_fd = bpf_map__fd(bpf->maps.time);

};

//Add state info to relevant_state_info_map
void populate_stateinfo_map(){
	for(int i = 0; i < FAULT_COUNT; i++){
		for(int j = 0; j <STATE_PROPERTIES_COUNT;j++){
			if(faults[i].initial.fault_type_conditions[j] != 0){
				int error;
				struct info_key information = {
					faults[i].pid,
					j
				};
				faults[i].relevant_conditions++;
				struct info_state *new_information_state = (struct info_state*)malloc(sizeof(struct info_state));

				new_information_state->current_value = 0;

				new_information_state->relevant_states[i] = faults[i].initial.fault_type_conditions[j];

				new_information_state->repeat = faults[i].repeat;

				if (constants.faultsverbose)
					printf("FAULT %d state info pos[%d] is %d conditions match is [%d] with pid %d \n",i,j,new_information_state->relevant_states[i],faults[i].initial.conditions_match[i],faults[i].pid);

				struct info_state *old_information_state = (struct info_state*)malloc(sizeof(struct info_state));

				old_information_state->current_value = 0;

				int exists = 0;
				exists = bpf_map_lookup_or_try_init_user(constants.relevant_state_info_fd,&information,new_information_state,old_information_state);

				//if already exists add
				if(exists){
					printf("It already exists \n");
					old_information_state->relevant_states[i] = faults[i].initial.fault_type_conditions[j];
					printf("State info is %llu \n",old_information_state->relevant_states[i]);
					error = bpf_map_update_elem(constants.relevant_state_info_fd,&information,old_information_state,BPF_ANY);
					if (error){
						printf("Error of update is %d, key->%d \n",error,j);	
					}
					free(new_information_state->relevant_states);
				}else{
					free(old_information_state->relevant_states);
				}

			}
		}

		if(strlen(faults[i].file_open)>0){
			struct relevant_fds relevant_fd_init = {};
			int pid = faults[i].pid;
			bpf_map_update_elem(constants.relevant_fd,&pid,&relevant_fd_init);
		}


	}


}

//Add name of files to eBPF map, one per pid
// void populate_files_map(){
// 	for(int i=0;i<FAULT_COUNT;i++){
// 		if(!faults[i].file_open)
// 			continue;
// 		if (strlen(faults[i].file_open)!=0){
// 			int error;
// 			//We pass the pid to filter out irrelevant pids opening
// 			int pid = faults[i].pid;

// 			struct file_info_simple file_info = {};
// 			strcpy(file_info.filename,faults[i].file_open);
// 			file_info.size = strlen(file_info.filename);

// 			error = bpf_map_update_elem(constants.files,&pid,&file_info,BPF_ANY);
// 			if (error){
// 				printf("Error of update in files_opened is %d, value->%s \n",error,faults[i].file_open);	
// 			}

// 			struct relevant_fds relevant_fd_init = {};
// 			bpf_map_update_elem(constants.relevant_fd,&pid,&relevant_fd_init);

// 			error = bpf_map_update_elem(constants.relevant_fd,&pid,&relevant_fd_init,BPF_ANY);
// 			if (error){
// 				printf("Error of update in files_opened is %d, value->%d \n",error,pid);	
// 			}

// 		}
// 	}
// }

void count_time(){

	while(1){
		sleep(1);
		constants.time += 1000;
		//int error = bpf_map_update_elem(constants.time_map_fd,&pos,&constants.time,BPF_ANY);
		// if (error){
		// 	printf("Error of update in count_time is %d\n",error);	
		// }
		//printf("New time is %d \n",(constants.time/1000));

		for (int i = 0; i< FAULT_COUNT;i++){
			int fault_time = faults[i].initial.fault_type_conditions[TIME_FAULT];
			int time_sec = (constants.time/1000);
			if (fault_time == time_sec){

				struct simplified_fault fault;

				int err_lookup;
				err_lookup = bpf_map_lookup_elem(constants.bpf_map_fault_fd, &i,&fault);
				if (err_lookup){
					printf("Did not find elem in count_time errno is %d \n",errno);
				}
				printf("Fault %d done:%d \n",i,fault.done);
				if (fault.done)
					continue;

				fault.initial.conditions_match[TIME_FAULT] = 1;
				printf("Changing Time to true \n");
				int error = bpf_map_update_elem(constants.bpf_map_fault_fd,&i,&fault,BPF_ANY);
				if(error)
					printf("Error of update in adding fault to bpf is %d \n",error);
			}
		}
	}
}

int main(int argc, char **argv)
{

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	int err_args;
	/* Parse command line arguments */
	err_args = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err_args)
		return err_args;

	
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct aux_bpf *aux_bpf = start_aux_maps();

	if(!aux_bpf){
		printf("Error in creating aux_bpf_maps\n");
		return 0;
	}

	get_fd_of_maps(aux_bpf);

	//if(constants.faultsverbose)
	print_block("Building Faults and Nodes");
		
	nodes = build_nodes();
	faults = build_faults_extra();
	NODE_COUNT = get_node_count();
	FAULT_COUNT = get_fault_count();

	print_fault_schedule(nodes,faults);
	

	setup_node_scripts();
	
	setup_begin_conditions();

	add_faults_to_bpf();

	//Add to all networkdevices

	char **device_names = get_device_names(DEVICE_COUNT);
	init_tc((NODE_COUNT)*2);
	struct tc_bpf *tc_ebpf_progs[NODE_COUNT];
	//struct tc_bpf *tc_ebpf_progs_tracking[DEVICE_COUNT];


	for (int i = 0;i<NODE_COUNT;i++)
		tc_ebpf_progs[i] = NULL;
	
	// for (int i = 0;i<DEVICE_COUNT;i++)
	// 	tc_ebpf_progs_tracking[i] = NULL;
		
		
	if(setup_tc_progs(tc_ebpf_progs	))
		goto cleanup;

	int tc_ebpf_progs_counter = 0;

	free(device_names);


	struct fs_bpf* fs_bpf;
	struct process_bpf* process_bpf;
	struct faultinject_bpf* faultinject_bpf;
	struct block_bpf* block_bpf;
	struct javagc_bpf* usdtjava_bpf;

	if(!constants.uprobemode){
		fs_bpf = monitor_fs();
		process_bpf = exec_and_exit(FAULT_COUNT);
		faultinject_bpf = fault_inject(FAULT_COUNT,constants.timemode);
		block_bpf = monitor_disk();
		//usdtjava_bpf = usdtjava(faults[0].pid,FAULT_COUNT,constants.timemode);

		printf("Created all structs \n");
		
		if (!fs_bpf){
			printf("Error in creating fs tracing\n");
			goto cleanup;			
		}

		if (!process_bpf){
			printf("Error in creating process_tracing \n");
			goto cleanup;		
		}
		if (!faultinject_bpf){
			printf("Error in creating fault injection bpf\n");
			goto cleanup;		
		}

		if (!block_bpf){
			printf("Error in creating disk monitor \n");
			goto cleanup;
		}
	}
	
	
	int err;
	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(aux_bpf->maps.rb), handle_event, NULL, NULL);
	
	constants.time=0;
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, count_time, NULL);
	start_node_scripts();

	while (!exiting) {
		err = ring_buffer__poll(rb, -1 /* timeout, ms */);
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


	cleanup:

	for(int i =0; i< NODE_COUNT;i++){
		if(strlen(nodes[i].script)){
			kill(nodes[i].pid,9);
		}
	}

	//Destroy eBPF stuff
    printf("Running cleanup \n"); 
	if(!block_bpf)
		block_bpf__destroy(block_bpf);
	if(!process_bpf)
		process_bpf__destroy(process_bpf);
	if(!faultinject_bpf)
		faultinject_bpf__destroy(faultinject_bpf);
	if(!aux_bpf)
		aux_bpf__destroy(aux_bpf);
	if(!fs_bpf)
		fs_bpf__destroy(fs_bpf);
	if(!rb)
		ring_buffer__free(rb);

	printf("Deleting tc_hooks \n");

	tc_ebpf_progs_counter = 0;
	for(int i = 0; i <FAULT_COUNT;i++){
		tc_ebpf_progs_counter = delete_tc_hook(tc_ebpf_progs,faults[i].faulttype,tc_ebpf_progs_counter);
	}

	printf("Deleting uprobes \n");
	for (int i = 0;i<FAULT_COUNT;i++){
		for (int j=0;j<MAX_FUNCTIONS;j++){
			if(faults[i].list_of_functions[j] != NULL)
				uprobes_bpf__destroy(faults[i].list_of_functions[j]);
		}
	}

	printf("Freeing structures \n");

	free(faults);

	printf("Finished cleanup \n"); 

	
	return 0;
}

void setup_node_scripts(){
	print_block("Setting up scripts");

	for(int i=0;i<NODE_COUNT;i++){
		if(!nodes[i].script){
			printf("Command is NULL \n");
			continue;
		}
		if(!nodes[i].script[0]){
			//printf("No command in this node %d \n",i);
			continue;
		}
		if (!strlen(nodes[i].script)){
			printf("Empty command \n");
			continue;
		} 
		if(constants.faultsverbose)
			printf("Starting processes with command %s \n",nodes[i].script);

		FILE *fp = start_target_process(i);
		nodes[i].pid = constants.target_pid;
		//TODO CHANGE PID IN EBPF
		printf("Starting process with pid is %d \n",nodes[i].pid);
	}
}


void start_node_scripts(){
	printf("Resuming Processes \n");
	for(int i=0;i<NODE_COUNT;i++){
		if(nodes[i].pid){
			printf("Sending signal to %d \n",nodes[i].pid);
			kill(nodes[i].pid,SIGUSR1);
		}
	}
}

//prints output of process we started
void print_output(void* args){
	char inLine[1024];
	FILE *fp = ((struct process_args*)args)->fp;
	int counter = 0;
	printf("Reading input for pid %d \n",((struct process_args*)args)->pid);

    while (fgets(inLine, sizeof(inLine), fp) != NULL)
    {
		if(counter==0){
			((struct process_args*)args)->pid= atoi(inLine);
			printf("PID is %d \n",atoi(inLine));
			counter++;
		}else{
       		printf("%s\n", inLine);
		}
    }
}

FILE* start_target_process(int node_number){

	char script[STRING_SIZE];

	char *args_script[STRING_SIZE];

	char *token = strtok(nodes[node_number].script," ");
	
	strcpy(script,token);
	args_script[0]=(char*)malloc(STRING_SIZE*sizeof(char));
	strcpy(args_script[0],token);

	int pos = 1;
	token = strtok(NULL," ");
	
	while( token != NULL ) {

		args_script[pos]=(char*)malloc(STRING_SIZE*sizeof(char));
		strcpy(args_script[pos],token);

		token = strtok(NULL," ");
		pos++;
   }
   args_script[pos]= NULL;

	FILE *fp = custom_popen(script,args_script,'r',&constants.target_pid);

	if (!fp)
    {
        perror("popen failed:");
        exit(1);
    }

	pthread_t thread_id;

	struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

	args->fp= fp;
	args->pid = constants.target_pid;
	pthread_create(&thread_id, NULL, print_output, (void*)args);

	return fp;

}


void setup_begin_conditions(){

	print_block("Adding relevant conditions, file_names and uprobes to kernel");

	for(int i = 0; i < FAULT_COUNT; i++){

		int user_func_cond_nr = 0;
		int has_time_condition = 0;
		for(int j = 0; j <faults[i].relevant_conditions;j++){
			int type = faults[i].fault_conditions_begin[j].type;
			int target = faults[i].target;
			int pid = nodes[target].pid;
			int error;
			if(type == SYSCALL){

				systemcall syscall = faults[i].fault_conditions_begin[j].condition.syscall;

				int syscall_nr = syscall.syscall;
				insert_relevant_condition_in_ebpf(i,pid,syscall_nr,syscall.call_count);
			}
			if (type == FILE_SYSCALL){

				file_system_call syscall = faults[i].fault_conditions_begin[j].condition.file_system_call;

				struct file_info_simple file_info = {};
				if (strlen(syscall.file_name)){
					strcpy(file_info.filename,syscall.file_name);
					file_info.size = strlen(file_info.filename);
					printf("Created fileinfo with filename %s \n",file_info.filename);
				}
				if (strlen(syscall.directory_name)){
					strcpy(file_info.filename,syscall.directory_name);
					file_info.size = strlen(file_info.filename);
					printf("Created fileinfo with dirname %s \n",file_info.filename);
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
				faults[i].list_of_functions[user_func_cond_nr] = uprobe(pid,user_function.symbol,user_function.binary_location,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.timemode);
				insert_relevant_condition_in_ebpf(i,pid,faults[i].fault_conditions_begin[j].condition.user_function.cond_nr,user_function.call_count);
				user_func_cond_nr++;
			}
			if(type == TIME){
				int time = faults[i].fault_conditions_begin[j].condition.time;
				has_time_condition = time;
				insert_relevant_condition_in_ebpf(i,pid,TIME_FAULT,1);
			}
		}
		//printf("has_time_condition %d and relevant conditions %d \n",has_time_condition,faults[i].rel)
		if (has_time_condition && (faults[i].relevant_conditions == 1)){
			printf("Need to process all syscalls to check time \n");
			constants.timemode = 1;
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

	if (constants.faultsverbose)
		printf("FAULT %d state info pos[%d] is %d conditions match is [%d] with pid %d \n",fault_nr,cond_nr,new_information_state->relevant_states[fault_nr],faults[fault_nr].initial.conditions_match[fault_nr],pid);
	struct info_state *old_information_state = (struct info_state*)malloc(sizeof(struct info_state));

	old_information_state->current_value = 0;

	int exists = 0;
	exists = bpf_map_lookup_or_try_init_user(constants.relevant_state_info_fd,&information,new_information_state,old_information_state);

	//if already exists add
	if(exists){
		printf("It already exists \n");
		old_information_state->relevant_states[fault_nr] = call_count;
		printf("State info is %llu \n",old_information_state->relevant_states[fault_nr]);
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
		printf("Adding fault with type %d \n",faults[i].faulttype);
		struct simplified_fault new_fault;
		new_fault.faulttype = faults[i].faulttype;
		new_fault.done = faults[i].done;

		for(int j = 0; j <faults[i].relevant_conditions;j++){
			int type = faults[i].fault_conditions_begin[j].type;
			if(type == SYSCALL){
				systemcall syscall = faults[i].fault_conditions_begin[j].condition.syscall;
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
				printf("Fault %d has condition user_function %d with call_count %d \n",i,cond_nr,user_function.call_count);
			}
			if(type == TIME){
				new_fault.initial.fault_type_conditions[TIME_FAULT] = 1;
				printf("Fault %d has condition time %d with call_count %d \n",i,TIME_FAULT,1);
			}
		}

		if (faults[i].category == SYSCALL_FAULT){
			
		}
		if(faults[i].category == FILE_SYS_OP){

			int error;
			int pid = nodes[faults[i].target].pid;

			file_system_operation file_system_op;
			
			file_system_op = faults[i].fault_details.file_system_op;

			struct file_info_simple file_info = {};
			if (strlen(file_system_op.file_name)){
				strcpy(file_info.filename,file_system_op.file_name);
				file_info.size = strlen(file_info.filename);
				printf("Created fileinfo with filename %s with size %d\n",file_info.filename,file_info.size);
			}
			if (strlen(file_system_op.directory_name)){
				strcpy(file_info.filename,file_system_op.directory_name);
				file_info.size = strlen(file_info.filename);
				printf("Created fileinfo with dirname %s with size %d\n",file_info.filename,file_info.size);
			}
			
			int syscall_nr = file_system_op.syscall;

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
		new_fault.pid = nodes[faults[i].target].pid;
		new_fault.occurrences = faults[i].occurrences;
		printf("Occurrences:%d\n",new_fault.occurrences);
		new_fault.relevant_conditions = faults[i].relevant_conditions;
		new_fault.fault_nr = i;
		new_fault.repeat = faults[i].repeat;

		int error = bpf_map_update_elem(constants.bpf_map_fault_fd,&i,&new_fault,BPF_ANY);
		if (error)
			printf("Error of update in adding fault to bpf is %d \n",error);
	}
	
}

//Create TC programs, one for each interface 
int setup_tc_progs(struct tc_bpf **tc_ebpf_progs){
	print_block("Starting tc progs");
	int handle = 1;
	//Insert IPS to block in a network device, key->if_index value->list of ips
	int tc_ebpf_progs_counter = 0;
	for (int i =0;i<FAULT_COUNT;i++){

		if(faults[i].faulttype == BLOCK_IPS){

			int target = faults[i].target;
			int index = get_interface_index(nodes[target].veth);

			__be32 ips_to_block[MAX_IPS_BLOCKED] = {0};
			for (int k = 0; k < MAX_IPS_BLOCKED; k++){
				__be32 ip = faults[i].ips_blocked[k];

				if(ip){	

					//printf("IP to block is %u \n",ip);
					char str[INET_ADDRSTRLEN];

					inet_ntop(AF_INET,&ip, str, INET_ADDRSTRLEN);

					ips_to_block[k]=ip;
					printf("Going to block ip %s \n",str);
				}
			}

			__u32 index_in_unsigned = (__u32)index;
			int error = bpf_map_update_elem(constants.blocked_ips,&index_in_unsigned,&ips_to_block,BPF_ANY);
			if (error){
				printf("Error of update in blocked_ips is %d, key->%d \n",error,index);	
			}

			struct tc_bpf* tc_prog;
			if (constants.verbose)
				printf("Inserted in %s for faults \n",nodes[target].veth);

			printf("Created tc %d \n",tc_ebpf_progs_counter);

			tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_INGRESS);

			if (!tc_prog){
				printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
				return -1;		
			}
			tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			tc_ebpf_progs_counter++;

			printf("Created tc %d \n",tc_ebpf_progs_counter);
			tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_EGRESS);

			if (!tc_prog){
				printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
				return -1;		
			}
			tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			tc_ebpf_progs_counter++;
		}
		if (faults[i].faulttype == NETWORK_ISOLATION){
			int target = faults[i].target;
			int index = get_interface_index(nodes[target].veth);


			struct tc_bpf* tc_prog;
			__u32 index_in_unsigned = (__u32)index;
			printf("Created tc %d \n",tc_ebpf_progs_counter);
			tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_INGRESS);

			if (!tc_prog){
				printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
				return -1;		
			}
			tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			tc_ebpf_progs_counter++;

			printf("Created tc %d \n",tc_ebpf_progs_counter);
			tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_EGRESS);

			if (!tc_prog){
				printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
				return -1;		
			}
			tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			tc_ebpf_progs_counter++;
		}

		if(faults[i].faulttype == DROP_PACKETS){

			int target = faults[i].target;
			int index = get_interface_index(nodes[target].veth);


			struct tc_bpf* tc_prog;
			__u32 index_in_unsigned = (__u32)index;

			//only egress
			printf("Created tc %d \n",tc_ebpf_progs_counter);
			tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_EGRESS);

			if (!tc_prog){
				printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
				return -1;		
			}
			tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			tc_ebpf_progs_counter++;
		}
	
	

	}
	return 0;
}