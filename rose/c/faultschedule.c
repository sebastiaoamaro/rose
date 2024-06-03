
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
#include "aux.h"

#define NODE_COUNT 1
#define FAULT_COUNT 2

void create_execution_plan(execution_plan* exe_plan,char* setup_script,int setup_duration,char* workload_script){
    memset(exe_plan->setup.script,'\0',sizeof(setup_script));
    strcpy(exe_plan->setup.script,setup_script);
    exe_plan->setup.duration = setup_duration;
    exe_plan->setup.pid = 0;

    memset(exe_plan->workload.script,'\0',sizeof(workload_script));
    strcpy(exe_plan->workload.script,workload_script);
    exe_plan->workload.pid = 0;
}
void create_node(node* node, char* name,int pid, char* veth, char* ip, char* script,char* env,int container){

    memset(node->name,'\0',sizeof(name));
    strcpy(node->name,name);
    node->pid = pid;

    memset(node->veth,'\0',sizeof(veth));
    strcpy(node->veth,veth);

    memset(node->ip,'\0',sizeof(ip));
    strcpy(node->ip,ip);

    memset(node->script,'\0',sizeof(script));
    strcpy(node->script,script);

    memset(node->env,'\0',sizeof(env));
    strcpy(node->env,env);

    node->container = container;
}

int get_node_count(){
    return NODE_COUNT;
}

int get_fault_count(){
    return FAULT_COUNT;
}


void create_fault(struct fault* fault,char* name,int target, int faulttype,int fault_category,fault_details fault_details,int repeat,int occurrences,int duration,int condition_count){
    
    memset(fault->name,'\0',sizeof(name));
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

    for (int i = 0; i < MAX_FUNCTIONS; i++){
        fault->list_of_functions_in_container[i] = 0;
    }

}

void add_begin_condition(struct fault* fault,fault_condition fault_condition,int position){
    fault->fault_conditions_begin[position] = fault_condition;
}

void build_user_function(user_function* user_func,char* binary_location,char* symbol,int call_count){

    memset(user_func->binary_location,'\0',sizeof(user_func->binary_location));
    strncpy(user_func->binary_location,binary_location,strlen(binary_location));
    memset(user_func->symbol,'\0',sizeof(user_func->symbol));
    strncpy(user_func->symbol,symbol,strlen(symbol));
    user_func->call_count = call_count;
}

void build_file_syscall(file_system_call* file_syscall,int syscall, char* directory_name,char* file_name,int call_count){

    file_syscall->syscall = syscall;
    memset(file_syscall->directory_name,'\0',sizeof(directory_name));
    strcpy(file_syscall->directory_name,directory_name);

    memset(file_syscall->file_name,'\0',sizeof(file_name));
    strcpy(file_syscall->file_name,file_name);

    file_syscall->call_count = call_count;
}

void build_syscall(systemcall* syscall,int syscall_nr,int call_count){

    syscall->syscall = syscall_nr;
    syscall->call_count = call_count;
}


void add_ip_to_block_extra(struct block_ips* fault,char *string_ip,int pos,int direction){

		struct sockaddr_in sa;

		inet_pton(AF_INET,string_ip,&(sa.sin_addr));
        
        if(direction == 2)
		    fault->nodes_out[pos] = sa.sin_addr.s_addr;
        if(direction == 1)
		    fault->nodes_in[pos] = sa.sin_addr.s_addr;
}


void add_ip_to_block(struct fault* fault,char *string_ip,int pos){

		struct sockaddr_in sa;

		inet_pton(AF_INET,string_ip,&(sa.sin_addr));

		fault->ips_blocked[pos] = sa.sin_addr.s_addr;
}
execution_plan* build_execution_plan(){

    return NULL;
}
node* build_nodes(){
    node* nodes = ( node*)malloc(NODE_COUNT * sizeof(node));
    create_node(&nodes[0],"tendermint",0,"","","/home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/tendermint.sh","",0);

    return nodes;
}
fault* build_faults_extra(){
    fault* faults = ( fault*)malloc(FAULT_COUNT * sizeof(fault));
    fault_details fault_details0;
    file_system_operation file_syscall0;
    file_syscall0.syscall = 24;
    file_syscall0.syscall_condition = 19;
    strcpy(file_syscall0.directory_name,"");
    strcpy(file_syscall0.file_name,"/.tendermint/data");
    file_syscall0.success = 0;
    file_syscall0.return_value = -1;
    fault_details0.file_system_op = file_syscall0;
    create_fault(&faults[0],"change_fstat_result",0,24,3,fault_details0,0,0,0,2);

    fault_condition fault_condition_0_0;
    user_function user_func_0_0;
    fault_condition_0_0.type = USER_FUNCTION;
    build_user_function(&user_func_0_0,"/home/sebastiaoamaro/phd/tendermint/build/tendermint","github.com/tendermint/tendermint/libs/os.EnsureDir",1);
    fault_condition_0_0.condition.user_function = user_func_0_0;
    add_begin_condition(&faults[0],fault_condition_0_0,0);
    fault_condition fault_condition_0_1;
    systemcall syscall_0_1;
    fault_condition_0_1.type = SYSCALL;
    build_syscall(&syscall_0_1,15,1);
    fault_condition_0_1.condition.syscall = syscall_0_1;
    add_begin_condition(&faults[0],fault_condition_0_1,1);
    fault_details fault_details1;
    file_system_operation file_syscall1;
    file_syscall1.syscall = 25;
    file_syscall1.syscall_condition = 20;
    strcpy(file_syscall1.directory_name,"");
    strcpy(file_syscall1.file_name,"/.tendermint/data/priv.json");
    file_syscall1.success = 0;
    file_syscall1.return_value = -1;
    fault_details1.file_system_op = file_syscall1;
    create_fault(&faults[1],"change_open_result",0,25,3,fault_details1,0,0,0,1);

    fault_condition fault_condition_1_0;
    user_function user_func_1_0;
    fault_condition_1_0.type = USER_FUNCTION;
    build_user_function(&user_func_1_0,"/home/sebastiaoamaro/phd/tendermint/build/tendermint","github.com/tendermint/tendermint/libs/os.EnsureDir",3);
    fault_condition_1_0.condition.user_function = user_func_1_0;
    add_begin_condition(&faults[1],fault_condition_1_0,0);

    return faults;
}