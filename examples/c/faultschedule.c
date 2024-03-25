
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include "uprobes.skel.h"
#include "faultschedule.h"

#define NODE_COUNT 1
#define FAULT_COUNT 1

void create_node(node* node, char* name,int pid, char* veth, char* ip, char* script){

    strcpy(node->name,name);
    node->pid = pid;
    strcpy(node->veth,veth);
    strcpy(node->ip,ip);
    strcpy(node->script,script);
}

int get_node_count(){
    return NODE_COUNT;
}

int get_fault_count(){
    return FAULT_COUNT;
}


void create_fault(struct fault* fault,char* name,int target, int faulttype,int fault_category,fault_details fault_details,int repeat,int occurrences,int duration,int condition_count){
    strcpy(fault->name,name);
    fault->target = target;

    fault->fault_details = fault_details;
    fault->faulttype = faulttype;
    fault->category = fault_category;
	fault->done = 0;
	fault->repeat = repeat;
	fault->network_directions = 2;
	fault->duration = duration;
    fault->relevant_conditions = condition_count;
    fault->occurrences = occurrences;

    fault->fault_conditions_begin = (struct fault_condition*)malloc(condition_count*sizeof(struct fault_condition));
    //fault->list_of_functions = (struct uprobes_bpf*)malloc(MAX_FUNCTIONS*sizeof(struct uprobes_bpf));

}

void add_begin_condition(struct fault* fault,fault_condition fault_condition,int position){
    fault->fault_conditions_begin[position] = fault_condition;
}

void build_user_function(user_function* user_func,char* binary_location,char* symbol,int call_count){

    strcpy(user_func->binary_location,binary_location);
    strcpy(user_func->symbol,symbol);
    user_func->call_count = call_count;
}

void build_file_syscall(file_system_call* file_syscall,int syscall, char* directory_name,char* file_name,int call_count){

    file_syscall->syscall = syscall;
    strcpy(file_syscall->directory_name,directory_name);
    strcpy(file_syscall->file_name,file_name);
    file_syscall->call_count = call_count;
}

void build_syscall(systemcall* syscall,int syscall_nr,int call_count){

    syscall->syscall = syscall_nr;
    syscall->call_count = call_count;
}


void add_ip_to_block_extra(struct block_ips* fault,char *string_ip,int pos){

		struct sockaddr_in sa;

		inet_pton(AF_INET,string_ip,&(sa.sin_addr));

		fault->ips_blocked[pos] = sa.sin_addr.s_addr;
}


void add_ip_to_block(struct fault* fault,char *string_ip,int pos){

		struct sockaddr_in sa;

		inet_pton(AF_INET,string_ip,&(sa.sin_addr));

		fault->ips_blocked[pos] = sa.sin_addr.s_addr;
}


// node* build_nodes(){
//     node* nodes = (node*)malloc(node_count * sizeof(node));

// fault* build_faults_extra(){
//     fault* faults = (struct fault*)malloc(1*sizeof(struct fault));

// }
node* build_nodes(){
    node* nodes = ( node*)malloc(NODE_COUNT * sizeof(node));
    create_node(&nodes[0],"redpanda1",2007175,"","","");

    return nodes;
}
fault* build_faults_extra(){
    fault* faults = ( fault*)malloc(FAULT_COUNT * sizeof(fault));
    fault_details fault_details0;
    process_fault process_pause0;
    process_pause0.type = 14;
    fault_details0.process_fault = process_pause0;
    create_fault(&faults[0],"process_pause",0,14,3,fault_details0,0,0,5,1);

    fault_condition fault_condition_0_0;
    int time_0_0 = 5;
    fault_condition_0_0.type = TIME;
    fault_condition_0_0.condition.time = time_0_0;
    add_begin_condition(&faults[0],fault_condition_0_0,0);

    return faults;
}