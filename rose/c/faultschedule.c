
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
#define FAULT_COUNT 1


char* get_veth_interface_name(const char* container_name);


void create_tracer(tracer* tracer,char* tracer_location, char* pipe_location, char* functions_file,char* binary_path){

    memset(tracer->tracer_location,'\0',sizeof(tracer_location));
    strcpy(tracer->tracer_location,tracer_location);

    memset(tracer->pipe_location,'\0',sizeof(pipe_location));
    strcpy(tracer->pipe_location,pipe_location);

    memset(tracer->functions_file,'\0',sizeof(functions_file));
    strcpy(tracer->functions_file,functions_file);

    memset(tracer->binary_path,'\0',sizeof(binary_path));
    strcpy(tracer->binary_path,binary_path);

}
void create_execution_plan(execution_plan* exe_plan,char* setup_script,int setup_duration,char* workload_script,char* cleanup_script, int cleanup_time){
    
    memset(exe_plan->setup.script,'\0',sizeof(setup_script));
    strcpy(exe_plan->setup.script,setup_script);
    exe_plan->setup.duration = setup_duration;
    exe_plan->setup.pid = 0;

    memset(exe_plan->workload.script,'\0',sizeof(workload_script));
    strcpy(exe_plan->workload.script,workload_script);
    exe_plan->workload.pid = 0;

    memset(exe_plan->cleanup.script,'\0',sizeof(cleanup_script));
    strcpy(exe_plan->cleanup.script,cleanup_script);
    exe_plan->cleanup.pid = 0;
    exe_plan->cleanup.duration = cleanup_time;
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

    node->if_index = 0;


    if (container){
        char* interface_name = get_veth_interface_name(node->name);
        printf("Interface name is %s \n",interface_name);
            memset(node->veth,'\0',sizeof(interface_name));
            strcpy(node->veth,interface_name);
    }
}

int get_node_count(){
    return NODE_COUNT;
}

int get_fault_count(){
    return FAULT_COUNT;
}


void create_fault(struct fault* fault,char* name,int target,int traced, int faulttype,int fault_category,fault_details fault_details,int repeat,int occurrences,int duration,int condition_count,int exit){
    
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
    fault->exit = exit;

    fault->fault_conditions_begin = (struct fault_condition*)malloc(condition_count*sizeof(struct fault_condition));
    //fault->list_of_functions = (struct uprobes_bpf*)malloc(MAX_FUNCTIONS*sizeof(struct uprobes_bpf));

    // for (int i = 0; i < MAX_FUNCTIONS; i++){
    //     fault->list_of_functions_in_container[i] = 0;
    // }

}

void add_begin_condition(struct fault* fault,fault_condition fault_condition,int position){
    fault->fault_conditions_begin[position] = fault_condition;
}

void build_user_function(user_function* user_func,char* binary_location,char* symbol,int call_count,int offset){

    memset(user_func->binary_location,'\0',sizeof(user_func->binary_location));
    strcpy(user_func->binary_location,binary_location);
    memset(user_func->symbol,'\0',sizeof(user_func->symbol));
    strcpy(user_func->symbol,symbol);
    user_func->call_count = call_count;
    user_func->offset = offset;
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


char* get_veth_interface_name(const char* container_name) {
    static char veth_name[512];  // Use static to return the name
    char command[512];
    char buffer[512];
    int iflink = -1;

    // Get the iflink of the container's eth0 interface
    snprintf(command, sizeof(command), "docker exec -it %s bash -c 'cat /sys/class/net/eth0/iflink'", container_name);
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        perror("popen");
        return NULL;
    }

    if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        iflink = atoi(buffer);
    } else {
        fprintf(stderr, "Failed to get iflink\n");
        pclose(pipe);
        return NULL;
    }
    pclose(pipe);

    if (iflink <= 0) {
        fprintf(stderr, "Invalid iflink value\n");
        return NULL;
    }

    // Grep for the iflink value in veth* ifindex files
    snprintf(command, sizeof(command), "grep -l %d /sys/class/net/veth*/ifindex", iflink);
    pipe = popen(command, "r");
    if (!pipe) {
        perror("popen");
        return NULL;
    }

    if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        // Extract the veth interface name from the path
        char* start = strstr(buffer, "veth");
        if (start) {
            // Copy until the next '/'
            char* end = strchr(start, '/');
            if (end) {
                *end = '\0'; // Null-terminate the string
            }
            memset(veth_name,'\0',sizeof(start));
            strcpy(veth_name, start);
            veth_name[sizeof(veth_name) - 1] = '\0'; // Ensure null-termination
            pclose(pipe);
            return veth_name;
        }
    } else {
        fprintf(stderr, "Failed to find veth interface\n");
    }
    pclose(pipe);
    return NULL;
}
execution_plan* build_execution_plan(){
    execution_plan* exe_plan = ( execution_plan*)malloc(1 * sizeof(execution_plan));
    create_execution_plan(exe_plan,"",0,"","",0);
    return exe_plan;
}
 tracer* build_tracer(){
    tracer* deployment_tracer = (tracer*)malloc(1 * sizeof(tracer));
    create_tracer(deployment_tracer,"/home/sebastiaoamaro/phd/torefidevel/rosetracer/target/release/rosetracer","/tmp/containerpid","","");
    return deployment_tracer;
}
node* build_nodes(){
    node* nodes = ( node*)malloc(NODE_COUNT * sizeof(node));
    create_node(&nodes[0],"zookeeper",0,"","","/home/sebastiaoamaro/phd/rw/Anduril/ground_truth/zookeeper-3157/run-original-test.sh","",0,"","",0);

    return nodes;
}
fault* build_faults_extra(){
    fault* faults = ( fault*)malloc(FAULT_COUNT * sizeof(fault));
    fault_details fault_details0;
    syscall_operation syscall0;
    syscall0.syscall = 3;
    syscall0.success = 0;
    syscall0.return_value = 0;
    fault_details0.syscall = syscall0;
    create_fault(&faults[0],"write_fail",0,0,3,2,fault_details0,0,0,0,1,0);

    fault_condition fault_condition_0_0;
    file_system_call file_syscall_0_0;
    fault_condition_0_0.type = FILE_SYSCALL;
    build_file_syscall(&file_syscall_0_0,READ_FILE,"","snapshot.0",1);
    fault_condition_0_0.condition.file_system_call = file_syscall_0_0;
    add_begin_condition(&faults[0],fault_condition_0_0,0);

    return faults;
}