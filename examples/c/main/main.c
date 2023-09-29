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

//Modules
#include <aux.h>
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

void process_counter(const struct event *event,int stateinfo);
int process_tc(const struct event*);
void process_fs(const struct event*);
void inject_fault(int faulttype,int pid,int fault_id,int syscall_nr);

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

} constants;

static struct fault *faults;
static int FAULT_COUNT = 0;
static int DEVICE_COUNT = 0;

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
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	if(constants.faultsverbose)
		printf("Arrived here TYPE is %d \n",e->type);

	switch(e->type){
		case EXEC:
			process_counter(e,PROCESSES_OPENED);
		break;
		case EXIT:
			process_counter(e,PROCESSES_CLOSED);
		break;
		case WRITE_HOOK:
			process_counter(e,WRITES);
		break;
		case READ_HOOK:
			process_counter(e,READS);
		break;
		case FUNCTIONS:
			process_counter(e,CALLCOUNT);
		break;
		case TC:
			process_tc(e);
		break;
		case FSYS:
			process_fs(e);
		break;
		case THREAD:
			process_counter(e,THREADS_CREATED);
		break;
		case NEWFSTATAT_HOOK:
			process_counter(e,NEWFSTATAT_COUNT);
		break;
		case OPENNAT_HOOK:
			process_counter(e,OPENNAT_COUNT);
		break;
		case NEW_FSTATAT_SPECIFIC:
			process_on_or_off_cond(e,NEW_FSTATAT_SPECIFIC);
		break;

	}

	int i,j = 0;

	//Checks if we have a fault to inject
	for (i=0;i<FAULT_COUNT;i++){
		int run = 0;
		int relevant_conditions = 0;
		for (j=0;j<STATE_PROPERTIES_COUNT;j++){
			//Check if condition matches and if it is relevant
			if (faults[i].initial->fault_type_conditions[j]){
				relevant_conditions+=1;
				if (faults[i].initial->conditions_match[j]){
					run+=1;
				}
			}
		}
		//temporary for testing, basically OR
		if (run == relevant_conditions)
			if (!faults[i].done){
				if (faults[i].faulttype == NETWORK_ISOLATION ||faults[i].faulttype == DROP_PACKETS ||faults[i].faulttype == BLOCK_IPS)
					inject_fault(faults[i].faulttype,0,i,0);
				else
					inject_fault(faults[i].faulttype,faults[i].pid,i,e->syscall_nr);
			}

	}
 
	return 0;
}

void process_on_or_off_cond(const struct event *event,int stateinfo){
	for (int i=0; i<FAULT_COUNT;i++){
		if (faults[i].initial->fault_type_conditions[stateinfo]){
			if(strcmp(faults[i].file_open,event->filename) == 0){
				printf("File which caused us to change state is  %s \n",event->filename);
				faults[i].initial->conditions_match[stateinfo] = 1;
			}
		}
	}
}


void process_counter(const struct event *event,int stateinfo){
	for (int i=0; i<FAULT_COUNT;i++){
		if (faults[i].initial->fault_type_conditions[stateinfo]){
			if (event->state_condition == faults[i].initial->fault_type_conditions[stateinfo] && event->pid == faults[i].pid){
				faults[i].initial->conditions_match[stateinfo] = 1;
			}
			//What is this?
			if (faults[i].repeat){
				if (event->state_condition == faults[i].initial->fault_type_conditions[stateinfo]&& event->pid == faults[i].pid){
					faults[i].initial->conditions_match[stateinfo] = 1;
				}
			}
		}
	}
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

void process_fs(const struct event *event){
	//printf("Got event filename is %s\n",event->filename);

	//Iterate over faults and check files, then set file opened to true, can add map counters to fsys
}


//Tells eBPF via Maps to start a fault
void inject_fault(int faulttype,int pid,int fault_id,int syscall_nr){

	if (constants.faultsverbose)
		printf("Injecting fault in %d for pid %d and syscall_nr %d\n",faulttype,pid,syscall_nr);
	
	if(faulttype == PROCESS_KILL){
		kill(faults[fault_id].initial->fault_type_conditions[PROCESS_TO_KILL],9);
	}
	if(faulttype == STOP){
		kill(faults[fault_id].initial->fault_type_conditions[PROCESS_TO_KILL],SIGSTOP);
	}

	struct fault_key fault_to_inject = {
		pid,
		faulttype
	};	

	struct fault_description description_of_fault = {
		1,
		faults[fault_id].occurrences,
		faults[fault_id].return_value,
		syscall_nr
	};

	int error = bpf_map_update_elem(constants.faulttype_fd,&fault_to_inject,&description_of_fault,BPF_ANY);
	if (error)
		printf("Error of update is %d, faulttype->%d / value-> %d \n",error,faulttype,1);

	faults[fault_id].done = 1;
	
	faults[fault_id].faults_injected_counter++;
	//If fault is to be injected again clear conditions match
	if (faults[fault_id].repeat && (faults[fault_id].faults_injected_counter == faults[fault_id].occurrences)){
		faults[fault_id].done = 0;
		for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
			faults[fault_id].initial->conditions_match[i] = 0;
		}
	}

}

//Temporary way of creating faults
void build_faults(){

	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

	for(int i = 0; i < FAULT_COUNT;i++){
		int repeat = 1;
		int occurrences = 0;
		int network_directions = 2;
		int return_value = -2;

		// char *binary_location = "/home/sebastiaoamaro/phd/tendermint/build/tendermint";
		// char *args[] = {"/home/sebastiaoamaro/phd/tendermint/build/tendermint","init",NULL};
		char *binary_location;
		char *args[64];
		// char *args[] = {"/home/sebastiaoamaro/phd/tendermint/build/tendermint","node","--proxy_app=kvstore",NULL};
		build_fault(&faults[i],repeat,OPENAT_RET,occurrences,network_directions,return_value,args,0,binary_location);

		faults[i].initial->fault_type_conditions[WRITES] = 1;
		//faults[i].initial->fault_type_conditions[PROCESS_TO_KILL] = 225183;
	
		// char string_ips[32] = "172.19.0.2";

		// add_ip_to_block(&faults[0],string_ips,0);

		// char file_name[FILENAME_MAX] = ".tendermint/";

		// strcpy(faults[i].file_open,file_name);

		//char func_names[MAX_FUNCTIONS][FUNCNAME_MAX] = {":_ZN13FullCompactor12CompactFilesEPv"};
		//char func_names[MAX_FUNCTIONS][FUNCNAME_MAX] = {":github.com/cometbft/cometbft/statesync.(*syncer).Sync"};
		// char func_names[MAX_FUNCTIONS][FUNCNAME_MAX] = {":github.com/tendermint/tendermint/libs/os.EnsureDir"};
		// add_function_to_monitor(&faults[i],&func_names[0],0);
		//add_function_to_monitor(&faults[i],&func_names[1],1);

	}
	//FAULT 0
	// char *binary_location = "/home/sebastiaoamaro/phd/tendermint/build/tendermint";
	// char *args[] = {"/home/sebastiaoamaro/phd/tendermint/build/tendermint","node","--proxy_app=kvstore",NULL};
	// int network_directions = 2;
	// int occurrences = 3;
	// int repeat = 0;
	// int return_value = -20;
	// build_fault(&faults[0],repeat,NEWFSTATAT,occurrences,network_directions,return_value,args,0,binary_location);

	// faults[0].initial->fault_type_conditions[CALLCOUNT] = 1;
	// faults[0].initial->fault_type_conditions[NEW_FSTATAT_SPECIFIC] = 1;
	// faults[0].initial->fault_type_conditions[NEWFSTATAT_COUNT] = 1;

	// char file_name[FILENAME_MAX] = "/root/.tendermint/data";

	// strcpy(faults[0].file_open,file_name);

	// //TODO:This is causing overflows fix!!!
	// char func_names[MAX_FUNCTIONS][FUNCNAME_MAX] = {":github.com/tendermint/tendermint/libs/os.EnsureDir"};
	// add_function_to_monitor(&faults[0],&func_names[0],0);

	// //FAULT 1

	// char *binary_location2 = "";
	// char *args2[] = {""};

	// build_fault(&faults[1],1,OPENNAT,1,2,-1,args2,0,binary_location2);

	// faults[1].initial->fault_type_conditions[CALLCOUNT] = 1;
	// faults[1].initial->fault_type_conditions[NEWFSTATAT_COUNT] = 3;


	//GET PIDS AND NETDEVICES
	int fault_count = 0;
	int checkfile = 1;
	fp = fopen(constants.inputfilename, "r");
    if (fp == NULL){
		//printf("Input file not found \n");
        //exit(EXIT_FAILURE);
		checkfile = 0;
	}
	if (checkfile){
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

	add_faults_to_bpf();
}

void add_faults_to_bpf(){
	printf("Adding faults to the map \n");
	for (int i = 0; i < FAULT_COUNT; i++){
		bpf_map_update_elem(constants.bpf_map_fault_fd,&i,faults[i],BPF_ANY);
	}
}


void get_fd_of_maps (struct aux_bpf *bpf){
	constants.relevant_state_info_fd = bpf_map__fd(bpf->maps.relevant_state_info);
	constants.faulttype_fd = bpf_map__fd(bpf->maps.faulttype);
	constants.blocked_ips = bpf_map__fd(bpf->maps.blocked_ips);
	constants.files = bpf_map__fd(bpf->maps.files);
	constants.relevant_fd = bpf_map__fd(bpf->maps.relevant_fd);
	constants.bpf_map_fault_fd = bpf_map__fd(bpf->maps.relevant_fd);
};

void populate_stateinfo_map(){
	for(int i = 0; i < FAULT_COUNT; i++){
		for(int j = 0; j <STATE_PROPERTIES_COUNT;j++){
			if(faults[i].initial->fault_type_conditions[j] != 0){
				int error;
				struct info_key information = {
					faults[i].pid,
					j
				};

				struct info_state *new_information_state = (struct info_state*)malloc(sizeof(struct info_state));

				new_information_state->current_value = 0;

				new_information_state->relevant_states[i] = faults[i].initial->fault_type_conditions[j];

				new_information_state->repeat = faults[i].repeat;

				if (constants.faultsverbose)
					printf("FAULT %d state info pos[%d] is %llu with pid %d \n",i,j,new_information_state->relevant_states[i],faults[i].pid);

				struct info_state *old_information_state = (struct info_state*)malloc(sizeof(struct info_state));

				old_information_state->current_value = 0;

				int exists = 0;
				exists = bpf_map_lookup_or_try_init_user(constants.relevant_state_info_fd,&information,new_information_state,old_information_state);

				//if already exists add
				if(exists){
					printf("It already exists \n");
					old_information_state->relevant_states[i] = faults[i].initial->fault_type_conditions[j];
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

void populate_files_map(){
		//Insert info about files_open
	for(int i=0;i<FAULT_COUNT;i++){
		if(!faults[i].file_open)
			continue;
		if (strlen(faults[i].file_open)!=0){
			int error;
			//We pass the pid to filter out irrelevant pids opening
			int pid = faults[i].pid;

			struct file_info_simple file_info = {};
			strcpy(file_info.filename,faults[i].file_open);
			file_info.size = strlen(file_info.filename);

			error = bpf_map_update_elem(constants.files,&pid,&file_info,BPF_ANY);
			if (error){
				printf("Error of update in files_opened is %d, value->%s \n",error,faults[i].file_open);	
			}

			int zero = 0;

			error = bpf_map_update_elem(constants.relevant_fd,&pid,&zero,BPF_ANY);
			if (error){
				printf("Error of update in files_opened is %d, value->%d \n",error,pid);	
			}

		}
	}
}

int setup_tc_progs(struct tc_bpf **tc_ebpf_progs,struct tc_bpf **tc_ebpf_progs_tracking){
	int handle = 1;
	//Insert IPS to block in a network device, key->if_index value->list of ips
	int tc_ebpf_progs_counter = 0;
	for (int i =0; i<FAULT_COUNT;i++){

		if(!faults[i].veth)
			continue;
		if(strlen(faults[i].veth) == 0){
			continue;
		}

		int index = get_interface_index(faults[i].veth);

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
			printf("Inserted in %s for faults \n",faults[i].veth);


		if (faults[i].network_directions == 0){

			tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_INGRESS);

			if (!tc_prog){
				printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
				return -1;		
			}
			tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			tc_ebpf_progs_counter++;
			
		}
		if(faults[i].network_directions == 1){

			tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_EGRESS);

			if (!tc_prog){
				printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
				return -1;		
			}
			tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			tc_ebpf_progs_counter++;
		}
		if(faults[i].network_directions == 2){


			tc_prog = traffic_control(index_in_unsigned,tc_ebpf_progs_counter,tc_ebpf_progs_counter+handle,FAULT_COUNT,BPF_TC_INGRESS);

			if (!tc_prog){
				printf("Error in creating tc_prog with interface %s with index %u \n",faults[i].veth,index_in_unsigned);
				return -1;		
			}
			tc_ebpf_progs[tc_ebpf_progs_counter] = tc_prog;
			tc_ebpf_progs_counter++;

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

void print_output(FILE *fp){

	char inLine[1024];
    while (fgets(inLine, sizeof(inLine), fp) != NULL)
    {
        printf("%s\n", inLine);
    }
}

FILE* start_target_process(const char **args){

	printf("Args is %s \n",args[0]);
	FILE *fp = custom_popen(args[0],args,'r',&constants.target_pid);

	if (!fp)
    {
        perror("popen failed:");
        exit(1);
    }

	pthread_t thread_id;
	pthread_create(&thread_id, NULL, print_output, (void *)fp);

	return fp;

}

void start_processes(){
	if(constants.faultsverbose)
		printf("Starting processes \n");
	for(int i=0;i<FAULT_COUNT;i++){
		if(!faults[i].command[0]){
			printf("No command in this fault %d \n",i);
			continue;
		}
		if (!strlen(faults[i].command[0])){
			printf("Empty command \n");
			continue;
		} 
		if(constants.faultsverbose)
			printf("Starting processes with command %s \n",faults[i].command[0]);
		FILE *fp = start_target_process(faults[i].command);
		faults[i].pid = constants.target_pid;
		printf("Starting process with pid is %d \n",faults[i].pid);
	}
	//Make pid of all faults same as the first one that started the command
	for (int i=0;i<FAULT_COUNT;i++){
		if(i==0)
			continue;
		faults[i].pid = faults[0].pid;
	}
}

void resume_processes(){
	printf("Resuming Processes \n");
	for(int i=0;i<FAULT_COUNT;i++){
		if(faults[i].pid){
			kill(faults[i].pid,SIGUSR1);
		}
	}
}

int main(int argc, char **argv)
{

	//translate_pid(5);
	
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

	if(constants.faultsverbose)
		printf("Building faults \n");
	build_faults();
	if(constants.faultsverbose)
		printf("Built faults \n");
	//start process where we will inject faults

	start_processes();

	struct aux_bpf *aux_bpf = start_aux_maps();

	if(!aux_bpf){
		printf("Error in creating aux_bpf_maps \n");
		return 0;
	}

	get_fd_of_maps(aux_bpf);
	if(!constants.tracingmode){
		populate_stateinfo_map();

		populate_files_map();
		if (constants.faultsverbose)
			printf("Populated eBPF Maps \n");	
	}

	//Add to all networkdevices

	char **device_names = get_device_names(DEVICE_COUNT);
	if (constants.faultsverbose)
		printf("Starting TC \n");
	init_tc((FAULT_COUNT+DEVICE_COUNT)*2);
	if (constants.faultsverbose)
		printf("TC done \n");
	struct tc_bpf *tc_ebpf_progs[FAULT_COUNT];
	struct tc_bpf *tc_ebpf_progs_tracking[DEVICE_COUNT];

	//Create uprobes
	struct uprobes_bpf *uprobes[FAULT_COUNT][MAX_FUNCTIONS];

	for (int i = 0;i<FAULT_COUNT;i++)
		for (int j = 0;j<MAX_FUNCTIONS;j++)
			uprobes[i][j] = NULL;


	//We have different lists for devices from faults or generic insertion

	for (int i = 0;i<FAULT_COUNT;i++)
		tc_ebpf_progs[i] = NULL;
	
	for (int i = 0;i<DEVICE_COUNT;i++)
		tc_ebpf_progs_tracking[i] = NULL;
		
		
	if(setup_tc_progs(tc_ebpf_progs,tc_ebpf_progs_tracking))
		goto cleanup;

	int handle = 1;
	int tc_ebpf_progs_counter = 0;

	for (int i =0; i<DEVICE_COUNT;i++){

		bool already_exists = false;

		for (int j=0;j<FAULT_COUNT;j++){
			if (strlen(faults[j].veth)){
				if (strcmp(device_names[i],faults[j].veth) == 0){
					already_exists = true;
				}
			}	
		}
		if (already_exists)
			continue;

		int index = get_interface_index(device_names[i]);

		__u32 index_in_unsigned = (__u32)index;

		struct tc_bpf* tc_prog;

		//printf("Inserted in %s for tracking \n",device_names[i]);
		//handle must be different than 0 so add 1
		tc_prog = traffic_control(index_in_unsigned,i+FAULT_COUNT,i+FAULT_COUNT+handle,FAULT_COUNT,BPF_TC_INGRESS);

		if (!tc_prog){
			printf("Error in creating tc_prog_tracking with interface %s \n",device_names[i]);
			goto cleanup;		
		}
		tc_ebpf_progs_tracking[i] = tc_prog;

	}
	free(device_names);

	if (constants.faultsverbose)
		printf("Creating uprobes \n");
	for(int i = 0; i < FAULT_COUNT;i++){

		for (int j = 0; j<MAX_FUNCTIONS;j++){
			if (!strcmp(faults[i].func_names[j],"empty"))
				continue;
			if (constants.faultsverbose)
				printf("Fault is %d funcame is %s, pid is %d \n",i,faults[i].func_names[j],faults[i].pid);

			uprobes[i][j] = uprobe(faults[i].pid,faults[i].func_names[j],faults[i].binary_location,FAULT_COUNT);			
		}


	}

	struct fs_bpf* fs_bpf;
	struct process_bpf* process_bpf;
	struct faultinject_bpf* faultinject_bpf;
	struct block_bpf* block_bpf;
	struct ring_buffer *rb = NULL;

	if(!constants.uprobemode){
		fs_bpf = monitor_fs();
		process_bpf = exec_and_exit(FAULT_COUNT);
		faultinject_bpf = fault_inject(FAULT_COUNT);
		block_bpf = monitor_disk();

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
	rb = ring_buffer__new(bpf_map__fd(aux_bpf->maps.rb), handle_event, NULL, NULL);

	if(constants.target_pid)
		resume_processes();
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

	//Kill process we started
	if(constants.target_pid)
		kill(constants.target_pid,9);

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
		if(!faults[i].veth)
			continue;
		if(strlen(faults[i].veth) != 0){
			tc_ebpf_progs_counter = delete_tc_hook(tc_ebpf_progs,faults[i].network_directions,tc_ebpf_progs_counter);
		}
	}
	printf("Deleting tc_hooks_tracking \n");
	for(int i=0; i<DEVICE_COUNT;i++){

		if (tc_ebpf_progs_tracking[i] == NULL)
			continue;
		//printf("Deleting prog %d with pointer %u \n",i,tc_ebpf_progs[i]);
		err = bpf_tc_detach(get_tc_hook(i+FAULT_COUNT), get_tc_opts(i+FAULT_COUNT));
		if (err) {
			fprintf(stderr, "Failed to detach TC %d: %d\n", i,err);
		}
		//printf("Deleting hook_tracking %d \n",i);
		bpf_tc_hook_destroy(get_tc_hook(i+FAULT_COUNT));

		//printf("Destroying prog_tracking %d \n",i);
		tc_bpf__destroy(tc_ebpf_progs_tracking[i]);
	}
	printf("Deleting uprobes \n");
	for (int i = 0;i<FAULT_COUNT;i++){
		for (int j=0;j<MAX_FUNCTIONS;j++){
			if(uprobes[i][j] != NULL)
				uprobes_bpf__destroy(uprobes[i][j]);
		}
	}

	printf("Freeing structures \n");

	for (int i=0;i<FAULT_COUNT;i++){
		free(faults[i].initial->conditions_match);
		free(faults[i].initial); // double corrupt look later
		free(faults[i].end->conditions_match);
		free(faults[i].end);
		printf("Free fault number [%d] \n",i);
	}
	free(faults);

	printf("Finished cleanup \n"); 

	
	return 0;
}