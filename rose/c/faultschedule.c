
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

#define NODE_COUNT 5
#define FAULT_COUNT 13

void create_execution_plan(execution_plan* exe_plan,char* setup_script,int setup_duration,char* workload_script){
    memset(exe_plan->setup.script,'\0',sizeof(setup_script));
    strcpy(exe_plan->setup.script,setup_script);
    exe_plan->setup.duration = setup_duration;
    exe_plan->setup.pid = 0;

    memset(exe_plan->workload.script,'\0',sizeof(workload_script));
    strcpy(exe_plan->workload.script,workload_script);
    exe_plan->workload.pid = 0;
}
void create_node(node* node, char* name,int pid, char* veth, char* ip, char* script,char* env,int container,char *binary,char *leader_symbol,int leader){

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

    memset(node->binary,'\0',sizeof(binary));
    strcpy(node->binary,binary);

    memset(node->leader_symbol,'\0',sizeof(leader_symbol));
    strcpy(node->leader_symbol,leader_symbol);

    node->container = container;

    node->leader_probe = NULL;

    node->leader = leader;
}

int get_node_count(){
    return NODE_COUNT;
}

int get_fault_count(){
    return FAULT_COUNT;
}


void create_fault(struct fault* fault,char* name,int target,int traced, int faulttype,int fault_category,fault_details fault_details,int repeat,int occurrences,int duration,int condition_count){
    
    memset(fault->name,'\0',sizeof(name));
    strcpy(fault->name,name);
    fault->target = target;
    fault->traced = traced;
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
    execution_plan* exe_plan = ( execution_plan*)malloc(1 * sizeof(execution_plan));
    create_execution_plan(exe_plan,"/home/sebastiaoamaro/phd/torefidevel/schedules/reproducedbugs/redisraft/startrediscluster.sh",30,"");
    return exe_plan;
}
node* build_nodes(){
    node* nodes = ( node*)malloc(NODE_COUNT * sizeof(node));
    create_node(&nodes[0],"redis1",0,"","","","",1,"/redisraft.so","raft_become_leader",1);
    create_node(&nodes[1],"redis2",0,"","","","",1,"/redisraft.so","raft_become_leader",0);
    create_node(&nodes[2],"redis3",0,"","","","",1,"/redisraft.so","raft_become_leader",0);
    create_node(&nodes[3],"redis4",0,"","","","",1,"/redisraft.so","raft_become_leader",0);
    create_node(&nodes[4],"redis5",0,"","","","",1,"/redisraft.so","raft_become_leader",0);

    return nodes;
}
fault* build_faults_extra(){
    fault* faults = ( fault*)malloc(FAULT_COUNT * sizeof(fault));
    fault_details fault_details0;
    process_fault process_pause0;
    process_pause0.type = 14;
    fault_details0.process_fault = process_pause0;
    create_fault(&faults[0],"process_pause0",-2,1,14,1,fault_details0,0,0,5000,1);

    fault_condition fault_condition_0_0;
    int time_0_0 = 5000;
    fault_condition_0_0.type = TIME;
    fault_condition_0_0.condition.time = time_0_0;
    add_begin_condition(&faults[0],fault_condition_0_0,0);
    fault_details fault_details1;
    process_fault process_pause1;
    process_pause1.type = 14;
    fault_details1.process_fault = process_pause1;
    create_fault(&faults[1],"process_pause1",-2,2,14,1,fault_details1,0,0,5000,1);

    fault_condition fault_condition_1_0;
    int time_1_0 = 5000;
    fault_condition_1_0.type = TIME;
    fault_condition_1_0.condition.time = time_1_0;
    add_begin_condition(&faults[1],fault_condition_1_0,0);
    fault_details fault_details2;
    process_fault process_pause2;
    process_pause2.type = 14;
    fault_details2.process_fault = process_pause2;
    create_fault(&faults[2],"process_pause2",-2,3,14,1,fault_details2,0,0,5000,1);

    fault_condition fault_condition_2_0;
    int time_2_0 = 5000;
    fault_condition_2_0.type = TIME;
    fault_condition_2_0.condition.time = time_2_0;
    add_begin_condition(&faults[2],fault_condition_2_0,0);
    fault_details fault_details3;
    process_fault process_pause3;
    process_pause3.type = 14;
    fault_details3.process_fault = process_pause3;
    create_fault(&faults[3],"process_pause4",-2,1,14,1,fault_details3,0,0,5000,1);

    fault_condition fault_condition_3_0;
    int time_3_0 = 25000;
    fault_condition_3_0.type = TIME;
    fault_condition_3_0.condition.time = time_3_0;
    add_begin_condition(&faults[3],fault_condition_3_0,0);
    fault_details fault_details4;
    process_fault process_pause4;
    process_pause4.type = 14;
    fault_details4.process_fault = process_pause4;
    create_fault(&faults[4],"process_pause5",-2,2,14,1,fault_details4,0,0,5000,1);

    fault_condition fault_condition_4_0;
    int time_4_0 = 25000;
    fault_condition_4_0.type = TIME;
    fault_condition_4_0.condition.time = time_4_0;
    add_begin_condition(&faults[4],fault_condition_4_0,0);
    fault_details fault_details5;
    process_fault process_pause5;
    process_pause5.type = 14;
    fault_details5.process_fault = process_pause5;
    create_fault(&faults[5],"process_pause6",-2,3,14,1,fault_details5,0,0,5000,1);

    fault_condition fault_condition_5_0;
    int time_5_0 = 25000;
    fault_condition_5_0.type = TIME;
    fault_condition_5_0.condition.time = time_5_0;
    add_begin_condition(&faults[5],fault_condition_5_0,0);
    fault_details fault_details6;
    process_fault process_pause6;
    process_pause6.type = 14;
    fault_details6.process_fault = process_pause6;
    create_fault(&faults[6],"process_pause7",-2,1,14,1,fault_details6,0,0,5000,1);

    fault_condition fault_condition_6_0;
    int time_6_0 = 45000;
    fault_condition_6_0.type = TIME;
    fault_condition_6_0.condition.time = time_6_0;
    add_begin_condition(&faults[6],fault_condition_6_0,0);
    fault_details fault_details7;
    process_fault process_pause7;
    process_pause7.type = 14;
    fault_details7.process_fault = process_pause7;
    create_fault(&faults[7],"process_pause8",-2,2,14,1,fault_details7,0,0,5000,1);

    fault_condition fault_condition_7_0;
    int time_7_0 = 45000;
    fault_condition_7_0.type = TIME;
    fault_condition_7_0.condition.time = time_7_0;
    add_begin_condition(&faults[7],fault_condition_7_0,0);
    fault_details fault_details8;
    process_fault process_pause8;
    process_pause8.type = 14;
    fault_details8.process_fault = process_pause8;
    create_fault(&faults[8],"process_pause9",-2,3,14,1,fault_details8,0,0,5000,1);

    fault_condition fault_condition_8_0;
    int time_8_0 = 45000;
    fault_condition_8_0.type = TIME;
    fault_condition_8_0.condition.time = time_8_0;
    add_begin_condition(&faults[8],fault_condition_8_0,0);
    fault_details fault_details9;
    process_fault process_pause9;
    process_pause9.type = 14;
    fault_details9.process_fault = process_pause9;
    create_fault(&faults[9],"pause_primary",-1,0,14,1,fault_details9,0,0,5000,1);

    fault_condition fault_condition_9_0;
    int time_9_0 = 65000;
    fault_condition_9_0.type = TIME;
    fault_condition_9_0.condition.time = time_9_0;
    add_begin_condition(&faults[9],fault_condition_9_0,0);
    fault_details fault_details10;
    process_fault process_pause10;
    process_pause10.type = 14;
    fault_details10.process_fault = process_pause10;
    create_fault(&faults[10],"process_pause10",-2,1,14,1,fault_details10,0,0,5000,1);

    fault_condition fault_condition_10_0;
    int time_10_0 = 85000;
    fault_condition_10_0.type = TIME;
    fault_condition_10_0.condition.time = time_10_0;
    add_begin_condition(&faults[10],fault_condition_10_0,0);
    fault_details fault_details11;
    process_fault process_pause11;
    process_pause11.type = 14;
    fault_details11.process_fault = process_pause11;
    create_fault(&faults[11],"process_pause11",-2,2,14,1,fault_details11,0,0,5000,1);

    fault_condition fault_condition_11_0;
    int time_11_0 = 85000;
    fault_condition_11_0.type = TIME;
    fault_condition_11_0.condition.time = time_11_0;
    add_begin_condition(&faults[11],fault_condition_11_0,0);
    fault_details fault_details12;
    process_fault process_pause12;
    process_pause12.type = 14;
    fault_details12.process_fault = process_pause12;
    create_fault(&faults[12],"process_pause12",-2,3,14,1,fault_details12,0,0,5000,1);

    fault_condition fault_condition_12_0;
    int time_12_0 = 85000;
    fault_condition_12_0.type = TIME;
    fault_condition_12_0.condition.time = time_12_0;
    add_begin_condition(&faults[12],fault_condition_12_0,0);

    return faults;
}