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
#include <ifaddrs.h>

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

void process_exec_exit(const struct event*);
void process_write(const struct event*);
int process_tc(const struct event*);
void process_fs(const struct event*);

void inject_fault(int faulttype,int pid,int fault_id);

const char *argp_program_version = "Tool for FI 0.01";
const char *argp_program_bug_address = "sebastiao.amaro@ŧecnico.ulisboa.pt";
const char argp_program_doc[] = "eBPF Fault Injection Tool.\n"
				"\n"
				"USAGE: ./main/main [-f fault count] [-d network device count] [-p process ids] \n";

static const struct argp_option opts[] = {
	{ "faultcount", 'f', "FAULTCOUNT", 0, "Number of faults" },
	{ "devicecount", 'd', "DEVICECOUNT", 0, "Number of network devices" },
	{ "processid", 'p', "PID", 0, "Process ID" },
	{ "inputfile", 'i', "inputfilename",0,"File with auxiliary fault information "},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static struct constants {
	bool verbose;
	long min_duration_ms;
	int faulttype_fd;
	int relevant_state_info_fd;
	int blocked_ips;
	int files;
	int pid;
	char *inputfilename;
} constants;

static struct fault *faults;
static int FAULT_COUNT = 0;
static int DEVICE_COUNT = 0;
static int FAULTS_INJECTED = 0;

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


//Handles events received from ringbuf (eBPF)
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	//printf("Arrived here TYPE is %d \n",e->type);

	switch(e->type){
		case EXEC_EXIT:
			process_exec_exit(e);
		break;
		case WRITE_HOOK:
			process_write(e);
		break;
		case READ_HOOK:
			process_read(e);
		break;
		case TC:
			process_tc(e);
		break;
		case FSYS:
			process_fs(e);
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
		//printf("run is %d, relevant_conditions is %d \n",run,relevant_conditions);
		if (run == relevant_conditions)
			if (!faults[i].done){
				if (faults[i].faulttype == (NETWORK_ISOLATION || DROP_PACKETS || BLOCK_IPS))
					inject_fault(faults[i].faulttype,0,i);
				else
					inject_fault(faults[i].faulttype,faults[i].pid,i);
			}

	}
 
	return 0;
}

//Handles start and stop of processes
void process_exec_exit(const struct event *event){
	int i = 0;

	for (i=0; i<FAULT_COUNT;i++){
		if (faults[i].initial->fault_type_conditions[PROCESSES_OPENED]){
			if (event->state_condition == faults[i].initial->fault_type_conditions[PROCESSES_OPENED] && event->pid == faults[i].pid){
				faults[i].initial->conditions_match[PROCESSES_OPENED] = 1;
			}
		}
		if (faults[i].initial->fault_type_conditions[PROCESSES_CLOSED]){
			if (event->state_condition == faults[i].initial->fault_type_conditions[PROCESSES_CLOSED] && event->pid == faults[i].pid){
				faults[i].initial->conditions_match[PROCESSES_CLOSED] = 1;
			}
		}
	}
}


//Handles the writes_syscall
void process_write(const struct event *event){
	for (int i=0; i<FAULT_COUNT;i++){
		if (faults[i].initial->fault_type_conditions[WRITES]){
			if (event->state_condition == faults[i].initial->fault_type_conditions[WRITES]&& event->pid == faults[i].pid){
				faults[i].initial->conditions_match[WRITES] = 1;
			}

			if (faults[i].repeat){
				if (event->state_condition == faults[i].initial->fault_type_conditions[WRITES]&& event->pid == faults[i].pid){
					faults[i].initial->conditions_match[WRITES] = 1;
				}
			}
		}
	}
}

//Handles the read syscall
void process_read(const struct event *event){
	for (int i=0; i<FAULT_COUNT;i++){
		if (faults[i].initial->fault_type_conditions[READS]){
			if (event->state_condition == faults[i].initial->fault_type_conditions[READS] && event->pid == faults[i].pid){
				faults[i].initial->conditions_match[READS] = 1;
			}

			if (faults[i].repeat){
				if (event->state_condition == faults[i].initial->fault_type_conditions[READS]&& event->pid == faults[i].pid){
					faults[i].initial->conditions_match[READS] = 1;
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
}


//Tells eBPF via Maps to start a fault
void inject_fault(int faulttype,int pid,int fault_id){

	//printf("Injecting fault in %d for pid %d \n",faulttype,pid);

	int error;

	struct fault_key fault_to_inject = {
		pid,
		faulttype
	};	

	struct fault_description description_of_fault = {
		1,
		faults[fault_id].occurrences,
	};

	error = bpf_map_update_elem(constants.faulttype_fd,&fault_to_inject,&description_of_fault,BPF_ANY);
	if (error)
		printf("Error of update is %d, faulttype->%d / value-> %d \n",error,faulttype,1);

	faults[fault_id].done = 1;

	//If fault is to be injected again clear conditions match
	if (faults[fault_id].repeat){
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

	for(int i = 0; i< FAULT_COUNT;i++){
		build_fault(&faults[i],1,TEMP_EMPTY,5);

		// faults[i].initial->fault_type_conditions[PROCESSES_OPENED] = 1;
		// faults[i].initial->fault_type_conditions[PROCESSES_CLOSED] = 1;
		faults[i].initial->fault_type_conditions[WRITES] = 50;
		faults[i].initial->fault_type_conditions[READS] = 50;
		//faults[0].initial->fault_type_conditions[FILES_OPENED_ANY] = ANY_PID;
	
		// char string_ips[32] = "172.19.0.2";

		// add_ip_to_block(&faults[0],string_ips,0);

		char file_name[FILENAME_MAX] = "test.txt";

		strcpy(faults[i].file_open,file_name);

		char func_names[8][FUNCNAME_MAX] = {":rocksdb_put",":rocksdb_get"};

		add_function_to_monitor(&faults[i],&func_names[0],i);
		add_function_to_monitor(&faults[i],&func_names[1],i);

	}

	int fault_count = 0;
	fp = fopen(constants.inputfilename, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);
		
	while ((read = getline(&line, &len, fp)) != -1) {
        printf("Line is %s \n", line);

		int pid;

		char *if_name;

		char* token = strtok(line,";");

		pid = atoi(token);

		faults[fault_count].pid = pid;

		token = strtok(NULL,"");

		char* ptr = strchr(token, '\n');
        if (ptr) {
            // if new line found replace with null character
            *ptr = '\0';
        }
		printf("Token is %s and len is %d \n",ptr,strlen(ptr));

		if(ptr)
			set_if_name(&faults[fault_count],ptr);

		fault_count++;

    }

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
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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

	int err_args;
	/* Parse command line arguments */
	err_args = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err_args)
		return err_args;
	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	//bump_memlock_rlimit();

	//constants.verbose = true;
	
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	build_faults();
	struct aux_bpf *aux_bpf = start_aux_maps();

	if(!aux_bpf){
		printf("Error in creating aux_bpf_maps \n");
		return 0;
	}

	constants.relevant_state_info_fd = bpf_map__fd(aux_bpf->maps.relevant_state_info);
	constants.faulttype_fd = bpf_map__fd(aux_bpf->maps.faulttype);
	constants.blocked_ips = bpf_map__fd(aux_bpf->maps.blocked_ips);
	constants.files = bpf_map__fd(aux_bpf->maps.files);


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
						printf("Error of update is %d, key->%llu \n",error,j);	
					}
					free(new_information_state->relevant_states);
				}else{
					free(old_information_state->relevant_states);
				}

			}
		}
	}


	//Insert info about files_open
	for(int i=0;i<FAULT_COUNT;i++){
		if (strlen(faults[i].file_open)!=0){
			int error;
			int value = ANY_PID;
			printf("Fault %i has file open %s \n",i,faults[i].file_open);

			struct file_info_simple file_info = {};
			strcpy(file_info.filename,faults[i].file_open);
			file_info.size = strlen(file_info.filename);

			error = bpf_map_update_elem(constants.files,&value,&file_info,BPF_ANY);
			if (error){
				printf("Error of update in files_opened is %d, key->%s \n",error,faults[i].file_open);	
			}	
		}
	}

	//Add to all networkdevices
	struct ifaddrs *ifaddr;

	int count_devices = 0;

	char **device_names;

	device_names = malloc(32*sizeof(char*));

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs \n");
		exit(EXIT_FAILURE);
	}

	/* Walk through linked list, maintaining head pointer so we can free list later. */
	//printf("Getting if names \n");

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL && count_devices < DEVICE_COUNT; ifa = ifa->ifa_next) {
		
		device_names[count_devices] = malloc(32*sizeof(char));
        sprintf(device_names[count_devices++], "%s", ifa->ifa_name);
    }

    freeifaddrs(ifaddr);

	printf("Printing names \n");

	for (int i=0;i<count_devices;i++){
		printf("Device name is %s \n",device_names[i]);
	}

	init_tc(FAULT_COUNT+DEVICE_COUNT);

	struct tc_bpf *tc_ebpf_progs[FAULT_COUNT];
	struct tc_bpf *tc_ebpf_progs_tracking[DEVICE_COUNT];

	//Create uprobes
	struct uprobe_bpf *uprobes[FAULT_COUNT][MAX_FUNCTIONS];

	for (int i = 0;i<FAULT_COUNT;i++)
		for (int j = 0;j<MAX_FUNCTIONS;j++)
			uprobes[i][j] = NULL;


	//We have different progs for different network devices

	for (int i = 0;i<FAULT_COUNT;i++)
		tc_ebpf_progs[i] = NULL;
	
	for (int i = 0;i<DEVICE_COUNT;i++)
		tc_ebpf_progs_tracking[i] = NULL;
		


	int handle = 1;
	//Insert IPS to block in a network device, key->if_index value->list of ips
	for (int i =0; i<FAULT_COUNT;i++){

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
		//printf("Inserted in %s for faults \n",faults[i].veth);

		//handle must be different than 0 so add 1
		tc_prog = traffic_control(index_in_unsigned,i,i+handle,FAULT_COUNT);

		if (!tc_prog){
			printf("Error in creating tc_prog with interface %s \n",faults[i].veth);
			goto cleanup;		
		}
		tc_ebpf_progs[i] = tc_prog;

	}

	for (int i =0; i<DEVICE_COUNT;i++){

		bool already_exists = false;

		for (int j=0;j<FAULT_COUNT;j++){
			if (faults[j].veth){
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
		tc_prog = traffic_control(index_in_unsigned,i+FAULT_COUNT,i+FAULT_COUNT+handle,FAULT_COUNT);

		if (!tc_prog){
			printf("Error in creating tc_prog_tracking with interface %s \n",device_names[i]);
			goto cleanup;		
		}
		tc_ebpf_progs_tracking[i] = tc_prog;

	}
	free(device_names);


	for(int i = 0; i < FAULT_COUNT;i++){

		for (int j = 0; j<MAX_FUNCTIONS;j++){
			if (!strcmp(faults[i].func_names[j],"empty"))
				continue;
			printf("Fault is %d funcame is %s, pid is %d \n",i,faults[i].func_names[j],faults[i].pid);

			uprobes[i][j] = uprobe(faults[i].pid,faults[i].func_names[j]);
		}


	}

	struct fs_bpf* fs_bpf = monitor_fs();
	struct process_bpf* process_bpf = exec_and_exit(FAULT_COUNT);
	struct faultinject_bpf* faultinject_bpf = fault_inject(FAULT_COUNT);
	struct block_bpf* block_bpf = monitor_disk();
	//struct uprobe_bpf* uprobe_bpf = uprobe(0,funcname);
	struct ring_buffer *rb = NULL;


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
	
	// if (!uprobe_bpf){
	// 	printf("Error in creating uprobe \n");
	// 	goto cleanup;
	// }
	
	int err;
	rb = ring_buffer__new(bpf_map__fd(aux_bpf->maps.rb), handle_event, NULL, NULL);

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
	// if(!uprobe_bpf)
	// 	uprobes_bpf__destroy(uprobe_bpf);
	if(!rb)
		ring_buffer__free(rb);

	printf("Deleting tc_hooks \n");
	for(int i=0; i<FAULT_COUNT;i++){

		if(strlen(faults[i].veth) == 0)
			continue;
		//printf("Deleting prog %d with pointer %u \n",i,tc_ebpf_progs[i]);
		err = bpf_tc_detach(get_tc_hook(i), get_tc_opts(i));
		if (err) {
			fprintf(stderr, "Failed to detach TC faults %d: %d\n", i,err);
		}

		//printf("Deleting hook %d \n",i);
		bpf_tc_hook_destroy(get_tc_hook(i));

		//printf("Destroying prog %d \n",i);
		tc_bpf__destroy(tc_ebpf_progs[i]);
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
		free(faults[i].initial->fault_type_conditions);
		free(faults[i].initial->conditions_match);
		free(faults[i].initial);
		free(faults[i].end->fault_type_conditions);
		free(faults[i].end->conditions_match);
		free(faults[i].end);
		printf("Free fault number [%d] \n",i);
	}
	free(faults);

	printf("Finished cleanup \n"); 

	
	return 0;
}