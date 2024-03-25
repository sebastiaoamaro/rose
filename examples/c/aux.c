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
#include <ifaddrs.h>
#include "faultschedule.h"
#include "aux.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

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

	err = bpf_map__unpin(skel->maps.funcnames, "/sys/fs/bpf/funcnames");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.funcnames, "/sys/fs/bpf/funcnames");
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

	err = bpf_map__unpin(skel->maps.active_write_fd, "/sys/fs/bpf/active_write_fd");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.active_write_fd, "/sys/fs/bpf/active_write_fd");
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

	err = bpf_map__unpin(skel->maps.time, "/sys/fs/bpf/time");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}

	err = bpf_map__pin(skel->maps.time, "/sys/fs/bpf/time");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return NULL;
	}


    return skel;

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

int get_interface_names(char** device_names,int device_count){
	//Add to all networkdevices
	struct ifaddrs *ifaddr;

	int count_devices = 0;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs \n");
		exit(EXIT_FAILURE);
	}

	/* Walk through linked list, maintaining head pointer so we can free list later. */

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL && count_devices < device_count; ifa = ifa->ifa_next) {
		
		device_names[count_devices] = malloc(32*sizeof(char));
        sprintf(device_names[count_devices++], "%s", ifa->ifa_name);
    }

    freeifaddrs(ifaddr);

	return count_devices;
}

void build_fault(struct fault* fault, int repeat,int faulttype,int occurrences,int duration, int network_directions,int return_value,char **command,int container_pid,char *binary_location){
	fault->done = 0;
	fault->repeat = repeat;
	fault->pid = 0;
	fault->faulttype = faulttype;
	// fault->initial = (struct faultstate*)malloc(sizeof(struct faultstate));
	// fault->end = (struct faultstate*)malloc(sizeof(struct faultstate));
	fault->network_directions = network_directions;
	fault->return_value = return_value;
	fault->container_pid = container_pid;
	fault->relevant_conditions = 0;
	fault->duration = duration;

	if(binary_location)
		strcpy(fault->binary_location,binary_location);
	//fault->initial->fault_type_conditions = (__u64*)malloc(STATE_PROPERTIES_COUNT * sizeof(__u64));
	//fault->initial->conditions_match = (int*)malloc(STATE_PROPERTIES_COUNT * sizeof(int));

	//fault->faulttype_count = (int*)malloc(FAULTSSUPPORTED*sizeof(int));

	for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
		fault->initial.conditions_match[i] = 0;
	}
	for (int i=0; i < STATE_PROPERTIES_COUNT;i++){
		fault->initial.fault_type_conditions[i] = 0;
	}

	for (int i=0; i < FAULTSSUPPORTED;i++){
		//fault->faulttype_count[i] = 0;
	}

	if(faulttype != TEMP_EMPTY){
		//fault->faulttype_count[faulttype] = occurrences;
		fault->occurrences = occurrences;
	}
	
	char string[64] = "empty";
	//I do not remember what this was for
	for(int i=0;i<MAX_FUNCTIONS;i++){
		strcpy(fault->func_names[i],string);
	}

	if(command){
		fault->command = (char**)malloc(FUNCNAME_MAX*MAX_ARGS*sizeof(char));
		memcpy(fault->command,command,sizeof(command)*MAX_ARGS);
	}
	// for(int i = 0;i<MAX_ARGS;i++){
	// 	if(!command[i])
	// 		break;
	// 	strcpy(fault->command[i],command[i]);
	// }

}


void set_if_name(struct fault* fault, char*if_name){
		fault->veth = (char*)malloc(sizeof(char)*sizeof(if_name));
		strcpy(fault->veth,if_name);	
}


void add_function_to_monitor(struct fault* fault, char *funcname,int pos){
	printf("Funcname in aux.c is %s \n",funcname);
	strcpy(fault->func_names[pos],funcname);
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
int translate_pid(int pid){

	char result[100];

	char chr_pid[10];

	sprintf(chr_pid,"%d",pid);

	strcpy(result,"/proc/");

	strcat(result,chr_pid);

	strcat(result,"/status");

	printf("result is %s \n ",result);

	FILE *fptr;

	fptr = fopen(result, "r");


	char inLine[1024];
    while (fgets(inLine, sizeof(inLine), fptr) != NULL)
    {
		if(strstr(inLine,"NSpid"))
       		printf("%s\n", inLine);
    }


	return pid;
}

void pause_process(void* args){

	int pid = *((struct process_pause_args*)args)->pid;
	int duration = *((struct process_pause_args*)args)->duration;
	send_signal(pid,SIGSTOP);
	printf("Sleeping for %d \n",duration);
	sleep(duration);
	send_signal(pid,SIGCONT);
}
int send_signal(int pid, int signal){
	printf("Sending %d to %d \n",signal,pid);
	kill(pid,signal);
}


void print_fault_schedule(node* nodes, fault * faults){

	for(int i = 0;i<get_node_count();i++){
		printf("Node name:%s | pid:%d | veth:%s | script:%s \n", nodes[i].name,nodes[i].pid,nodes[i].veth,nodes[i].script);
	}

	for(int i=0;i<get_fault_count();i++){
		printf("Fault name:%s | type:%d | target:%d \n",faults[i].name,faults[i].faulttype,faults[i].target);

		switch(faults[i].faulttype){
			case WRITE: case READ: case CLONE:
				break;
			case NETWORK_ISOLATION:
				break;
			case BLOCK_IPS:
				block_ips block_ips = faults[i].fault_details.block_ips;
				printf("block_ips count is %d \n",block_ips.count);
				for(int i = 0; i < block_ips.count; i++){
					if (block_ips.ips_blocked[i])
						printf("ip_blocked: %u \n",block_ips.ips_blocked[i]);
				}
				break;
			case DROP_PACKETS:
				break;
			case WRITE_FILE: case READ_FILE: case WRITE_RET: case READ_RET: case OPEN:
			case MKDIR: case NEWFSTATAT:  case OPENAT: case NEWFSTATAT_RET: case OPENAT_RET:
				break;
			case PROCESS_KILL: case PROCESS_STOP:
				break;
		}

		for(int j = 0; j < faults[i].relevant_conditions; j++){
			int condition_type = faults[i].fault_conditions_begin[j].type;

			switch(condition_type){
				case 0:
					user_function user_function = faults[i].fault_conditions_begin[j].condition.user_function;

					printf("User function condition symbol: %s | binary: %s | call_count: %d \n",user_function.symbol,user_function.binary_location,user_function.call_count);

					break;
				case 1:
					file_system_call file_system_call = faults[i].fault_conditions_begin[j].condition.file_system_call;

					printf("File syscall nr: %d | dir_name: %s | file_name: %s | call_couunt: %d \n",file_system_call.syscall,file_system_call.directory_name,file_system_call.file_name,file_system_call.call_count);
					break;
				case 2:
					systemcall syscall = faults[i].fault_conditions_begin[j].condition.syscall;

					printf("Syscall nr: %d | call_count:%d \n",syscall.syscall,syscall.call_count);
					break;
				case 3:
					int time = faults[i].fault_conditions_begin[j].condition.time;
					printf("Time is %d \n",time);

					break;
			}
		}
	}
}

void print_block(char* sentence){
	printf("###########################################################\n");
	printf("###########################################################\n");
	printf("%s\n",sentence);
	printf("###########################################################\n");
	printf("###########################################################\n");
}