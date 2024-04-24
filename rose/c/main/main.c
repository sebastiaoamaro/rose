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
// #include <tc.h>
// #include <tc.skel.h>
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
//int setup_tc_progs(struct tc_bpf **tc_ebpf_progs);
void insert_relevant_condition_in_ebpf(int fault_nr,int pid,int cond_nr,int call_count);
void count_time();
void get_fd_of_maps (struct aux_bpf *bpf);
static int handle_event(void *ctx, void *data, size_t data_sz);
void run_setup();
void collect_node_pids();
void print_output(void* args);

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
static execution_plan* plan;
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


int main(int argc, char **argv)
{

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	//printf("PID is %d \n",get_container_pid("redpanda0"));

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
		
	plan = build_execution_plan();
	nodes = build_nodes();
	faults = build_faults_extra();
	NODE_COUNT = get_node_count();
	FAULT_COUNT = get_fault_count();


	print_fault_schedule(plan,nodes,faults);
	
	run_setup();

	collect_node_pids();

	setup_node_scripts();
	
	setup_begin_conditions();

	add_faults_to_bpf();

	//Add to all networkdevices

	// char **device_names = get_device_names(DEVICE_COUNT);
	// init_tc((NODE_COUNT)*2);
	// struct tc_bpf *tc_ebpf_progs[NODE_COUNT];
	//struct tc_bpf *tc_ebpf_progs_tracking[DEVICE_COUNT];


	// for (int i = 0;i<NODE_COUNT;i++)
	// 	tc_ebpf_progs[i] = NULL;
	
	// for (int i = 0;i<DEVICE_COUNT;i++)
	// 	tc_ebpf_progs_tracking[i] = NULL;
		
		
	setup_tc_progs();
	// 	goto cleanup;

	// int tc_ebpf_progs_counter = 0;

	//free(device_names);


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
		if(nodes[i].pid_tc_in >0){
			kill(nodes[i].pid_tc_in,SIGINT);
		}
		if(nodes[i].pid_tc_out >0){
			kill(nodes[i].pid_tc_out,SIGINT);
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

	// tc_ebpf_progs_counter = 0;
	// for(int i = 0; i <FAULT_COUNT;i++){
	// 	tc_ebpf_progs_counter = delete_tc_hook(tc_ebpf_progs,faults[i].faulttype,tc_ebpf_progs_counter);
	// }

	printf("Deleting uprobes \n");
	for (int i = 0;i<FAULT_COUNT;i++){
		for (int j=0;j<MAX_FUNCTIONS;j++){
			if(faults[i].list_of_functions[j] != NULL){
				printf("Destroying uprobe %d for FAULT %d \n",j,i);
				uprobes_bpf__destroy(faults[i].list_of_functions[j]);
			}
		}
	}

	printf("Freeing structures \n");

	free(faults);

	printf("Finished cleanup \n"); 

	
	return 0;
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

void run_setup(){
	print_block("Running setup script");

	char *args_script[STRING_SIZE];

	char *env_script[STRING_SIZE];


	args_script[0]=(char*)malloc(STRING_SIZE*sizeof(char));

	args_script[0]= NULL;

	env_script[0]=(char*)malloc(STRING_SIZE*sizeof(char));

	env_script[0]= NULL;


	if(plan->setup.script){
		printf("Starting setup \n");
		FILE *fp = custom_popen(plan->setup.script,args_script,env_script,'r',&(plan->setup.pid));

		pthread_t thread_id;

		struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

		args->fp= fp;
		args->pid = 0;
		pthread_create(&thread_id, NULL, print_output, (void*)args);
	}

	if(strlen(plan->workload.script)){
		printf("Starting workload \n");
		FILE *fp = custom_popen(plan->workload.script,args_script,env_script,'r',&(plan->workload.pid));
	}

	//Start setup
	kill(plan->setup.pid,SIGUSR1);

	//Sleep while we wait for setup to start
	if(plan->setup.duration >0){
		sleep(plan->setup.duration);
	}
}

void start_workload(){
	//Start workload
	kill(plan->workload.pid,SIGUSR1);
}

void collect_node_pids(){
	for(int i=0; i < NODE_COUNT;i++){
		if(nodes[i].pid == 0){
			int pid = get_container_pid(nodes[i].name);
			printf("New pid for %s is %d \n",nodes[i].name,pid);
			nodes[i].pid = pid;
		}
	}
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
		if(strlen(nodes[i].script)){
			printf("Sending signal to %d \n",nodes[i].pid);
			kill(nodes[i].pid,SIGUSR1);
		}
		if(nodes[i].pid_tc_in !=0){
			printf("Sending signal to start tc %d \n",nodes[i].pid_tc_in);
			kill(nodes[i].pid_tc_in,SIGUSR1);
		}
		if(nodes[i].pid_tc_out !=0){
			printf("Sending signal to start tc %d \n",nodes[i].pid_tc_out);
			kill(nodes[i].pid_tc_out,SIGUSR1);
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
		// if(counter==0){
		// 	((struct process_args*)args)->pid= atoi(inLine);
		// 	printf("PID is %d \n",atoi(inLine));
		// 	counter++;
		// }else{
       	// 	printf("%s\n", inLine);
		// }

		//printf("%s\n", inLine);
    }
}

FILE* start_target_process(int node_number){

	char script[STRING_SIZE];

	char *args_script[STRING_SIZE];

	char *env_script[STRING_SIZE];

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

	printf("Created script args \n");

	char *token_env = strtok(nodes[node_number].env," ");
	env_script[0]=(char*)malloc(STRING_SIZE*sizeof(char));

	int pos_env = 1;

	if(token_env != NULL){
		strcpy(env_script[0],token_env);
		pos_env = 0;
	}
		
	token_env = strtok(NULL," ");	

	while( token_env != NULL ) {

		env_script[pos_env]=(char*)malloc(STRING_SIZE*sizeof(char));
		strcpy(env_script[pos_env],token_env);

		token_env = strtok(NULL," ");
		pos++;
   	}
   	env_script[pos_env]= NULL;

	printf("Created env args \n");


	FILE *fp = custom_popen(script,args_script,env_script,'r',&constants.target_pid);

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
					strncpy(file_info.filename,syscall.file_name,strlen(syscall.file_name));
					file_info.size = strlen(file_info.filename);
					printf("Created fileinfo with filename %s \n",file_info.filename);
				}
				if (strlen(syscall.directory_name)){
					strncpy(file_info.filename,syscall.directory_name,strlen(syscall.directory_name));
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
				
				if(nodes[target].container){

					//Find the directory in hostnamespace
					char* dir = get_overlay2_location(nodes[target].name);

					//Combine paths
					char* combined_path = (char*)malloc(MAX_FILE_LOCATION_LEN * sizeof(char));
					snprintf(combined_path, MAX_FILE_LOCATION_LEN, "%s%s", dir, user_function.binary_location);


					faults[i].list_of_functions[user_func_cond_nr] = uprobe(pid,user_function.symbol,user_function.binary_location,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.timemode);
				}else{
					faults[i].list_of_functions[user_func_cond_nr] = uprobe(pid,user_function.symbol,user_function.binary_location,FAULT_COUNT,user_func_cond_nr+STATE_PROPERTIES_COUNT,constants.timemode);		
				}
				insert_relevant_condition_in_ebpf(i,pid,faults[i].fault_conditions_begin[j].condition.user_function.cond_nr,user_function.call_count);
				user_func_cond_nr++;
			}
			if(type == TIME){
				int time = faults[i].fault_conditions_begin[j].condition.time;
				faults[i].initial.fault_type_conditions[TIME_FAULT] = time;
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
		new_fault.run = 0;
		new_fault.faulttype = faults[i].faulttype;
		new_fault.done = faults[i].done;
		
		for(int k = 0; k < STATE_PROPERTIES_COUNT; k++){
			new_fault.initial.conditions_match[k] = 0;
		}

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
				new_fault.initial.fault_type_conditions[TIME_FAULT] = faults[i].fault_conditions_begin[j].condition.time;
				printf("Fault %d has condition time %d with call_count %d \n",i,TIME_FAULT,faults[i].fault_conditions_begin[j].condition.time);
			}
		}

		if (faults[i].category == SYSCALL_FAULT){
			new_fault.return_value = faults[i].fault_details.syscall.return_value;
		}
		if(faults[i].category == FILE_SYS_OP){

			int error;
			int pid = nodes[faults[i].target].pid;

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
			if (strlen(file_system_op.directory_name)){
				//memset(file_info.filename,'\0',sizeof(file_system_op.directory_name));
				strcpy(file_info.filename,file_system_op.directory_name);
				file_info.size = strlen(file_info.filename);
				printf("Created fileinfo with dirname %s with size %d for cond %d\n",file_info.filename,file_info.size,syscall_nr);
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
int setup_tc_progs(){
	print_block("Starting tc progs");
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


			printf("Created TC program number %d index is %d for network_direction %d\n",tc_ebpf_progs_counter,index,BPF_TC_EGRESS);

			__be32 ips_to_block_out[MAX_IPS_BLOCKED] = {0};

			for (int k = 0; k < faults[i].fault_details.block_ips.count_out; k++){

				//TODO FIX IPS_BLOCKED LIST
				__be32 ip = faults[i].fault_details.block_ips.nodes_out[k];

				if(ip){	

					char str[INET_ADDRSTRLEN];

					inet_ntop(AF_INET,&ip, str, INET_ADDRSTRLEN);

					ips_to_block_out[k]=ip;
					printf("Going to block ip %s \n",str);
				}
			}

			//TEMPORARY FIX FOR DOCKER DEPLOYMENTS
			__u32 index_in_unsigned = (__u32)index-1;

			struct tc_key egress_key = {
				index_in_unsigned,
				BPF_TC_EGRESS
			};

			int error = bpf_map_update_elem(constants.blocked_ips,&egress_key,&ips_to_block_out,BPF_ANY);
			if (error){
				printf("Error of update in blocked_ips is %d, key->%d \n",error,index);	
			}

			sprintf(nsenter_args[2], "%d", nodes[target].pid);
			sprintf(nsenter_args[5], "%u", index_in_unsigned);
			sprintf(nsenter_args[6], "%d", tc_ebpf_progs_counter);
			sprintf(nsenter_args[7], "%d", tc_ebpf_progs_counter+handle);
			sprintf(nsenter_args[8], "%d", FAULT_COUNT);
			sprintf(nsenter_args[9], "%d", BPF_TC_EGRESS);	

			
			FILE *fp = custom_popen(nsenter,nsenter_args,env_script,'r',&nodes[target].pid_tc_out);

			pthread_t thread_id;

			struct process_args *args = (struct process_args*)malloc(sizeof(struct process_args));

			args->fp= fp;
			args->pid = nodes[target].pid_tc_out;
			pthread_create(&thread_id, NULL, print_output, (void*)args);

			tc_ebpf_progs_counter++;

			pthread_t thread_id2;


			printf("Creating TC program number %d index is %d for network_direction %d\n",tc_ebpf_progs_counter,index,BPF_TC_INGRESS);

			__be32 ips_to_block_in[MAX_IPS_BLOCKED] = {0};

			for (int k = 0; k < faults[i].fault_details.block_ips.count_in; k++){

				//TODO FIX IPS_BLOCKED LIST
				__be32 ip = faults[i].fault_details.block_ips.nodes_in[k];

				if(ip){	

					char str[INET_ADDRSTRLEN];

					inet_ntop(AF_INET,&ip, str, INET_ADDRSTRLEN);

					ips_to_block_in[k]=ip;
					printf("Going to block ip %s \n",str);
				}
			}


			struct tc_key ingress_key = {
				index_in_unsigned,
				BPF_TC_INGRESS
			};

			error = bpf_map_update_elem(constants.blocked_ips,&index_in_unsigned,&ips_to_block_in,BPF_ANY);
			if (error){
				printf("Error of update in blocked_ips is %d, key->%d \n",error,index);	
			}


			sprintf(nsenter_args[6], "%d", tc_ebpf_progs_counter);
			sprintf(nsenter_args[7], "%d", tc_ebpf_progs_counter+handle);
			sprintf(nsenter_args[9], "%d", BPF_TC_INGRESS);	

			FILE *fp2 = custom_popen(nsenter,nsenter_args,env_script,'r',&nodes[target].pid_tc_in);

			struct process_args *args2 = (struct process_args*)malloc(sizeof(struct process_args));

			args2->fp= fp2;
			args2->pid = nodes[target].pid_tc_in;

			pthread_create(&thread_id2, NULL, print_output, (void*)args2);

			tc_ebpf_progs_counter++;

		}
		if (faults[i].faulttype == NETWORK_ISOLATION){
			int target = faults[i].target;
			int index = get_interface_index(nodes[target].veth);


			struct tc_bpf* tc_prog;
			__u32 index_in_unsigned = (__u32)index;
			printf("Created tc %d \n",tc_ebpf_progs_counter);
			// tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_INGRESS);

			// if (!tc_prog){
			// 	printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
			// 	return -1;		
			// }
			//tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			//tc_ebpf_progs_counter++;

			// printf("Created tc %d \n",tc_ebpf_progs_counter);
			// tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_EGRESS);

			// if (!tc_prog){
			// 	printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
			// 	return -1;		
			// }
			//tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			//tc_ebpf_progs_counter++;
		}

		if(faults[i].faulttype == DROP_PACKETS){

			int target = faults[i].target;
			int index = get_interface_index(nodes[target].veth);


			struct tc_bpf* tc_prog;
			__u32 index_in_unsigned = (__u32)index;

			//only egress
			printf("Created tc %d \n",tc_ebpf_progs_counter);
			//tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_EGRESS);

			// if (!tc_prog){
			// 	printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
			// 	return -1;		
			// }
			// tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			// tc_ebpf_progs_counter++;
		}
	
	

	}
	return 0;
}

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
			//=printf("Fault %d has fault_time %d \n",i,fault_time);
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
				fault.run+=1;
				printf("Changing Time to true \n");
				int error = bpf_map_update_elem(constants.bpf_map_fault_fd,&i,&fault,BPF_ANY);
				if(error)
					printf("Error of update in adding fault to bpf is %d \n",error);
			}
		}
	}
}

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