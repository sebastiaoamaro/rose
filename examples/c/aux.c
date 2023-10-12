#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "aux.skel.h"
#include <pthread.h>
#include "aux.h"
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

void build_fault(struct fault* fault, int repeat,int faulttype,int occurrences,int network_directions,int return_value,char **command,int container_pid,char *binary_location){
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
	fault->command = (char**)malloc(FUNCNAME_MAX*MAX_ARGS*sizeof(char));
	memcpy(fault->command,command,sizeof(command)*MAX_ARGS);
	// for(int i = 0;i<MAX_ARGS;i++){
	// 	if(!command[i])
	// 		break;
	// 	strcpy(fault->command[i],command[i]);
	// }

}

void add_ip_to_block(struct fault* fault,char *string_ip,int pos){

		struct sockaddr_in sa;

		inet_pton(AF_INET,string_ip,&(sa.sin_addr));

		fault->ips_blocked[pos] = sa.sin_addr.s_addr;
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