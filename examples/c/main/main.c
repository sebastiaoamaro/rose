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
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <ifaddrs.h>


void process_exec_exit(const struct event*);
void process_write(const struct event*);
int process_tc(const struct event*);
void process_fs(const struct event*);

void inject_fault(int syscall,int fault_id);

const char *argp_program_version = "Tool for FI 0.0";
const char *argp_program_bug_address = "sebastiao.amaro@ŧecnico.ulisboa.pt";
const char argp_program_doc[] = "eBPF Fault Injection Tool.\n"
				"\n"
				"USAGE: ./main/main [-f fault count] [-d network device count]\n";

static const struct argp_option opts[] = {
	{ "faultcount", 'f', "FAULTCOUNT", 0, "Number of faults" },
	{ "devicecount", 'd', "DEVICECOUNT", 0, "Number of network devices" },
	{},
};

static struct env {
	bool verbose;
	long min_duration_ms;
	int syscalls_to_fail_fd;
	int relevant_state_info_fd;
	int blocked_ips;
	int files;
} env;

static struct fault *faults;
static int FAULT_COUNT = 0;
static int DEVICE_COUNT = 0;


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
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
			if (faults[i].fault_type_conditions[j]){
				relevant_conditions+=1;
				if (faults[i].conditions_match[j]){
					run+=1;
				}
				else
					run-=1;
			}
		}
		//printf("run is %d, relevant_conditions is %d \n",run,relevant_conditions);
		if (run == relevant_conditions)
			if (!faults[i].done)
				inject_fault(faults[i].syscall,i);
	}
 
	return 0;
}

//Handles start and stop of processes
void process_exec_exit(const struct event *event){
	int i = 0;

	for (i=0; i<FAULT_COUNT;i++){
		if (faults[i].fault_type_conditions[PROCESSES_OPENED]){
			if (event->processes_created == faults[i].fault_type_conditions[PROCESSES_OPENED]){
				faults[i].conditions_match[PROCESSES_OPENED] = 1;
			}
		}
		if (faults[i].fault_type_conditions[PROCESSES_CLOSED]){
			if (event->processes_closed == faults[i].fault_type_conditions[PROCESSES_CLOSED]){
				faults[i].conditions_match[PROCESSES_CLOSED] = 1;
			}
		}
	}
}


//Handles the writes_syscall
void process_write(const struct event *event){
	for (int i=0; i<FAULT_COUNT;i++){
		if (faults[i].fault_type_conditions[WRITES]){
			//printf("Write count is %d \n",event->writes);
			if (event->writes == faults[i].fault_type_conditions[WRITES]){
				faults[i].conditions_match[WRITES] = 1;
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
void inject_fault(int syscall,int fault_id){

	printf("Injecting fault in %d \n",syscall);

	int error;
	int inject = 1;
	error = bpf_map_update_elem(env.syscalls_to_fail_fd,&syscall,&inject,BPF_ANY);
	if (error)
		printf("Error of update is %d, syscall->%d / value-> %d \n",error,syscall,inject);

	faults[fault_id].done = 1;

}

//Temporary way of creating faults
void build_faults(){
	//BUILD FAULT 1
	faults[0].done = 0;
	faults[0].syscall = TEMP_EMPTY;
	faults[0].fault_type_conditions = (__u64*)malloc(STATE_PROPERTIES_COUNT * sizeof(__u64));
	faults[0].conditions_match = (int*)malloc(STATE_PROPERTIES_COUNT * sizeof(int));
	for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
		faults[0].conditions_match[i] = 0;
	}
	for (int j=0; j < STATE_PROPERTIES_COUNT;j++){
		faults[0].fault_type_conditions[j] = 0;
	}

	faults[0].fault_type_conditions[PROCESSES_OPENED] = 0;
	faults[0].fault_type_conditions[PROCESSES_CLOSED] = 0;
	faults[0].fault_type_conditions[WRITES] = 300;
	//faults[0].fault_type_conditions[FILES_OPENED_ANY] = ANY_PID;
 

	//Weird
	char string_ips[1][32] = {"172.19.0.2"};

	for (int i = 0;i < 3;i++){

		struct sockaddr_in sa;

		inet_pton(AF_INET,string_ips[i],&(sa.sin_addr));

		faults[0].ips_blocked[i] = sa.sin_addr.s_addr;
	}

	// char if_name[32] = "veth0c5f1ea";

	// faults[0].veth = (char*)malloc(sizeof(char)*32);
	// strcpy(faults[0].veth,if_name);	


	char file_name[256] = "proc";

	strcpy(faults[0].file_open,file_name);

 	//BUILD FAULT 2
	// faults[1].syscall = TEMP_EMPTY;
	// faults[1].fault_type_conditions = (__u64*)malloc(STATE_PROPERTIES_COUNT * sizeof(__u64));
	// faults[1].conditions_match = (int*)malloc(STATE_PROPERTIES_COUNT * sizeof(int));
	// for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
	// 	faults[1].conditions_match[i] = 0;
	// }
	// for (int j=0; j < STATE_PROPERTIES_COUNT;j++){
	// 	faults[1].fault_type_conditions[j] = 0;
	// }

	// faults[1].fault_type_conditions[PROCESSES_OPENED] = 5;
	// faults[1].fault_type_conditions[PROCESSES_CLOSED] = 5;
	// faults[1].fault_type_conditions[WRITES] = 5;


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

	//env.verbose = true;
	
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	build_faults();
	struct aux_bpf *aux_bpf = start_aux_maps();

	if(!aux_bpf){
		printf("Error in creating aux_bpf_maps \n");
		return 0;
	}

	env.relevant_state_info_fd = bpf_map__fd(aux_bpf->maps.relevant_state_info);
	env.syscalls_to_fail_fd = bpf_map__fd(aux_bpf->maps.syscalls_to_fail);
	env.blocked_ips = bpf_map__fd(aux_bpf->maps.blocked_ips);
	env.files = bpf_map__fd(aux_bpf->maps.files);
	

	//Insert general properties in MAPS, mostly counters

	for(int j = 0 ; j<STATE_PROPERTIES_COUNT; j++){
		__u64 *relevant_state_info = (__u64)malloc(FAULT_COUNT*sizeof(__u64));
		int error;
		__u64 state_condition = j;
		//Count amount of faults that have a specific condition
		int relevant_state_info_counter = 0;
		for (int i = 0; i <FAULT_COUNT; i++){
			if (faults[i].fault_type_conditions[j] != 0){
				relevant_state_info_counter+=1;				
				relevant_state_info[i] = faults[i].fault_type_conditions[j];
				printf("FAULT %d state info pos[%d] is %llu \n",i,j,relevant_state_info[i]);

			}
		}

		//If more than 0 fault need this property add it to the map
		if (relevant_state_info_counter>0){
			//printf("Adding state info about [%llu] and had the amount of faults with this property is [%d]\n",state_condition,relevant_state_info_counter);

			for(int i=0;i<relevant_state_info_counter;i++){
				printf("Relevant value %llu \n",relevant_state_info[i]);
			}
			error = bpf_map_update_elem(env.relevant_state_info_fd,&state_condition,relevant_state_info,BPF_ANY);
		
			if (error){
				printf("Error of update is %d, key->%llu \n",error,state_condition);	
			}	
		}

	}

	for(int i=0;i<FAULT_COUNT;i++){
		if (strlen(faults[i].file_open)!=0){
			int error;
			int value = ANY_PID;
			printf("Fault %i has file open %s \n",i,faults[i].file_open);

			struct file_info_simple file_info = {};
			strcpy(file_info.filename,faults[i].file_open);
			file_info.size = strlen(file_info.filename);

			error = bpf_map_update_elem(env.files,&value,&file_info,BPF_ANY);
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

	/* Walk through linked list, maintaining head pointer so we
        can free list later. */
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

	struct tc_bpf *tc_ebpf_progs_tracking[DEVICE_COUNT];

	//We have different progs for different network devices
	struct tc_bpf *tc_ebpf_progs[FAULT_COUNT];

	int handle = 1;
	//Insert IPS to block in a network device, key->if_index value->list of ips
	for (int i =0; i<FAULT_COUNT;i++){

		if(!faults[i].veth){
			continue;
		}
		printf("Interface is %s and i is %d \n",faults[i].veth,i);
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
		int error = bpf_map_update_elem(env.blocked_ips,&index_in_unsigned,&ips_to_block,BPF_ANY);
		if (error){
			printf("Error of update in blocked_ips is %d, key->%d \n",error,index);	
		}

		struct tc_bpf* tc_prog;
		tc_prog = traffic_control(index_in_unsigned,i+handle,FAULT_COUNT);

		if (!tc_prog){
			printf("Error in creating tc_prog with interface %s \n",faults[i].veth);
			goto cleanup;		
		}
		tc_ebpf_progs[i] = tc_prog;

	}

	for (int i =0; i<DEVICE_COUNT;i++){

		int index = get_interface_index(device_names[i]);

		__u32 index_in_unsigned = (__u32)index;

		struct tc_bpf* tc_prog;

		tc_prog = traffic_control(index_in_unsigned,i+FAULT_COUNT+handle,FAULT_COUNT);

		if (!tc_prog){
			printf("Error in creating tc_prog_tracking with interface %s \n",device_names[i]);
			goto cleanup;		
		}
		tc_ebpf_progs_tracking[i] = tc_prog;

	}


	struct fs_bpf* fs_bpf = monitor_fs();
	struct process_bpf* process_bpf = exec_and_exit(FAULT_COUNT);
	struct faultinject_bpf* faultinject_bpf = fault_inject(FAULT_COUNT);
	struct block_bpf* block_bpf = monitor_disk();
	struct ring_buffer *rb = NULL;


	printf("Created monitor fs \n");
	
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
	if(!rb)
		ring_buffer__free(rb);

	printf("Deleting tc_hooks \n");
	for(int i=0; i<FAULT_COUNT;i++){

		if(!faults[i].veth)
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

	printf("Finished cleanup \n"); 

	
	return 0;
}