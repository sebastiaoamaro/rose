#ifndef __FAULTS_BPF_H
#define __FAULTS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


void process_counter(const struct event* event,int stateinfo);
void process_fs(const struct event* event);
int process_tc(const struct event* event);
void inject_fault(int faulttype,int pid,int fault_id,int syscall_nr);

int fault_nr = 16;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 128);
	__type(key, int);
	__type(value, struct fault);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faults SEC(".maps");

static inline int handle_event(struct event* e,int fault_count)
{
    //fault_nr = fault_count;
    int type = -1;
    if(e){
        if(e->type == NULL)
            return 0;
        type = e->type;
    }

	switch(type){
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
			//process_on_or_off_cond(e,NEW_FSTATAT_SPECIFIC);
		break;

	}

    int i,j = 0;

	//Checks if we have a fault to inject
	// for (i=0;i<fault_nr;i++){
	// 	int run = 0;
	// 	int relevant_conditions = 0;
    //     struct fault *fault = bpf_map_lookup_elem(&faults, &i);
	// 	for (j=0;j<STATE_PROPERTIES_COUNT;j++){
	// 		//Check if condition matches and if it is relevant
	// 		if (fault->initial->fault_type_conditions[j]){
	// 			relevant_conditions+=1;
	// 			if (fault->initial->conditions_match[j]){
	// 				run+=1;
	// 			}
	// 		}
	// 	}
	// 	//temporary for testing, basically OR
	// 	if (run == relevant_conditions)
	// 		if (!fault->done){
	// 			if (fault->faulttype == NETWORK_ISOLATION ||fault->faulttype == DROP_PACKETS ||fault->faulttype == BLOCK_IPS)
	// 				inject_fault(fault->faulttype,0,i,0);
	// 			else
	// 				inject_fault(fault->faulttype,fault->pid,i,e->syscall_nr);
	// 		}

	// }


}

void inject_fault(int faulttype,int pid,int fault_id,int syscall_nr){
}


void process_counter(const struct event* event,int stateinfo){
    for (int i=0; i<fault_nr;i++){
        struct fault *fault = bpf_map_lookup_elem(&faults, &i);
        if (fault){
            if(fault->initial){
                if (fault->initial->fault_type_conditions){
                    if (stateinfo < STATE_PROPERTIES_COUNT){
                        if (fault->initial->fault_type_conditions[stateinfo]){
                            if (event->state_condition == fault->initial->fault_type_conditions[stateinfo] && event->pid == fault->pid){
                                fault->initial->conditions_match[stateinfo] = 1;
                            }
                            //What is this?
                            if (fault->repeat){
                                if (event->state_condition == fault->initial->fault_type_conditions[stateinfo]&& event->pid == fault->pid){
                                    fault->initial->conditions_match[stateinfo] = 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

int process_tc(const struct event* event){

}

void process_fs(const struct event* event){

}
#endif /* __FS_BPF_H */