#include <argp.h>
#include <signal.h>
#include <stdio.h>
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

    err = bpf_map__unpin(skel->maps.faulttype, "/sys/fs/bpf/faulttype");
	if(err) {
		printf("[ERROR] libbpf unpin API: %d\n", err);
		//return NULL;
	}
	
	err = bpf_map__pin(skel->maps.faulttype, "/sys/fs/bpf/faulttype");
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


    return skel;

	err = bpf_map__pin(skel->maps.funcnames, "/sys/fs/bpf/funcnames");
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

void build_fault(struct fault* fault, int repeat, int pid,int faulttype,int occurences){
	fault->done = 0;
	fault->repeat = repeat;
	fault->faulttype = faulttype;
	fault->pid = pid;
	fault->initial = (struct faultstate*)malloc(sizeof(struct faultstate));
	fault->end = (struct faultstate*)malloc(sizeof(struct faultstate));

	fault->initial->fault_type_conditions = (__u64*)malloc(STATE_PROPERTIES_COUNT * sizeof(__u64));
	fault->initial->conditions_match = (int*)malloc(STATE_PROPERTIES_COUNT * sizeof(int));

	fault->faulttype_count = (int*)malloc(STATE_PROPERTIES_COUNT*sizeof(int));

	for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
		fault->initial->conditions_match[i] = 0;
	}
	for (int i=0; i < STATE_PROPERTIES_COUNT;i++){
		fault->initial->fault_type_conditions[i] = 0;
	}

	for (int i=0; i < FAULTSSUPPORTED;i++){
		fault->faulttype_count[i] = 0;
	}

	if(faulttype != TEMP_EMPTY)
		fault->faulttype_count[faulttype] = occurences;

	for(int i=0;i<MAX_FUNCTIONS;i++){
		char string[FUNCNAME_MAX] = "empty";
		strcpy(fault->func_names[i],string);
	}
}

void add_ip_to_block(struct fault* fault,char *string_ip,int pos){

		struct sockaddr_in sa;

		inet_pton(AF_INET,string_ip,&(sa.sin_addr));

		fault->ips_blocked[pos] = sa.sin_addr.s_addr;
}

void set_if_name(struct fault* fault, char*if_name){
		fault->veth = (char*)malloc(sizeof(char)*32);
		strcpy(fault->veth,if_name);	
}

void add_function_to_monitor(struct fault* fault, char *funcname,int pos){
	printf("Funcname in aux.c is %s \n",funcname);
	strcpy(fault->func_names[pos],funcname);
}