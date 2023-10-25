#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "faultinject.h"
#include "aux.h"
#include "fs.bpf.h"
#include "fs.h"


struct callback_ctx {
	int state_condition;
	int state_condition_value;
	int pid;
    int fault_count;
	struct bpf_map *faults_specification;
};

static inline void process_counter(int stateinfo,int state_condition_valuel,int pid,int fault_count,struct bpf_map *faults_specification,struct bpf_map *faults);
static inline void inject_fault(int faulttype,int pid,int syscall_nr, struct simplified_fault *fault,int pos,struct bpf_map *faults_specification);
static inline __u64 process(struct bpf_map *map, int *pos,struct simplified_fault *fault , struct callback_ctx *data);



///////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////STATE_PROCESSING/////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

static inline int process_current_state(int state_key, int pid,int fault_count,int time_mode,struct bpf_map *relevant_state_info,struct bpf_map *faults_specification,struct bpf_map *faults){

	struct info_key information = {
		pid,
		state_key
	};
	struct info_state *current_state;

	current_state = bpf_map_lookup_elem(relevant_state_info,&information);
	if (current_state){
		current_state->current_value++;
		int value = current_state->current_value;
		if(current_state->relevant_states){
			for (int i=0;i<fault_count;i++){
				if (current_state->relevant_states[i]){
					u64 relevant_value = current_state->relevant_states[i];
					if (relevant_value == value && relevant_value != 0){

						bpf_printk("Found relevant value for property %d \n",state_key);
						process_counter(state_key,value,pid,fault_count,faults_specification,faults);
					}
					if(current_state->repeat && (value % relevant_value == 0)){
						bpf_printk("Found relevant value and repeating\n");
						process_counter(state_key,relevant_value,pid,fault_count,faults_specification,faults);
					}
					//bpf_printk("Skipped \n");
					}
				}
				
		}
	}else{
		if(time_mode){
			process_counter(0,0,pid,fault_count,faults_specification,faults);
		}
	}
	return 0;
}

static inline void process_counter(int stateinfo,int state_condition_value, int pid,int fault_count,struct bpf_map *faults_specification,struct bpf_map *faults){
	struct callback_ctx data;
	data.state_condition = stateinfo;
	data.state_condition_value = state_condition_value;
	data.pid = pid;
    data.fault_count = fault_count;
	data.faults_specification = faults_specification;
	bpf_for_each_map_elem(faults,process,&data,BPF_ANY);
}

static inline  __u64 process(struct bpf_map *map, int *pos,struct simplified_fault *fault , struct callback_ctx *data){
    
    int fault_count = data->fault_count;
	if(*pos>=fault_count)
		return 1;
	struct bpf_map *faults_specification = data->faults_specification;
	int state_condition = data->state_condition;
	int pid = data->pid;
	int state_condition_value = data->state_condition_value;
	int conditions[STATE_PROPERTIES_COUNT];
        
	int relevant_conditions = fault->relevant_conditions;
	int run = 0;
	if (fault){
		if (fault->initial.fault_type_conditions){
			int *conditions = fault->initial.fault_type_conditions;
            if ((state_condition > STATE_PROPERTIES_COUNT) || (state_condition < 0))
                return 1;
			if (conditions[state_condition]){
				int condition_value = conditions[state_condition];
				if(state_condition_value > 0){
					if (state_condition_value == condition_value && pid == fault->pid){
                        if ((state_condition > STATE_PROPERTIES_COUNT) || (state_condition < 0))
                            return 1;
					 	__sync_fetch_and_add(&(fault->initial.conditions_match[state_condition]),1);
						bpf_printk("Changing to true property for fault %d in state key %d \n",*pos,state_condition);
                        //fault->initial.conditions_match[state_condition] = 1;
					}
				}
			}
		}
		for(int i = 0;i <STATE_PROPERTIES_COUNT;i++ ){
			if (fault->initial.fault_type_conditions[i]){
				if (fault->initial.conditions_match[i]){
					run+=1;
				}
			}
		}

		if (run == relevant_conditions){
			if (!fault->done){
				if (fault->faulttype == NETWORK_ISOLATION ||fault->faulttype == DROP_PACKETS ||fault->faulttype == BLOCK_IPS)
					inject_fault(fault->faulttype,0,0,fault,pos,faults_specification);
				else
					inject_fault(fault->faulttype,fault->pid,0,fault,pos,faults_specification);
			}
		}


	}
	return 0;
}	




static inline void inject_fault(int fault_type,int pid,int syscall_nr,struct simplified_fault *fault,int pos,struct bpf_map *faults_specification){

	bpf_printk("Injecting fault with fault_type %d \n",fault_type);
	if(fault_type == PROCESS_KILL){
		//kill(faults[fault_id].initial->fault_type_conditions[PROCESS_TO_KILL],9);
	}
	if(fault_type == STOP){
		//kill(faults[fault_id].initial->fault_type_conditions[PROCESS_TO_KILL],SIGSTOP);
	}

	struct fault_key fault_to_inject = {
		pid,
		fault_type
	};	
	if (fault){
			struct fault_description description_of_fault = {
				1,
				fault->occurrences,
				fault->return_value,
				syscall_nr
			};

			int error = bpf_map_update_elem(faults_specification,&fault_to_inject,&description_of_fault,BPF_ANY);
			if (error)
				bpf_printk("Error of update is %d, faulttype->%d / value-> %d \n",error,fault_type,1);

			fault->done = 1;
			
			fault->faults_injected_counter++;
			if (fault->repeat){
				fault->done = 0;
			}
			for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
				fault->initial.conditions_match[i] = 0;
			}


	}

}

static inline void inject_override(int pid,int fault,u64* counter, struct pt_regs* ctx,int syscall_nr,struct bpf_map* faults_specification){
	struct fault_key fault_to_inject = {
		pid,
		fault,
	};
	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(faults_specification,&fault_to_inject);

	if (description_of_fault){
			if (description_of_fault->on){
				if (*counter < description_of_fault->occurences){
					*counter+=1;
					u64 ts = bpf_ktime_get_ns();
					bpf_printk("Injected fault with return value %d at ts %u \n",description_of_fault->return_value,ts);
					bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

				}
				else if(description_of_fault->occurences == 0){
					u64 ts = bpf_ktime_get_ns();
					bpf_printk("Injected fault with return value %d at ts %u \n",description_of_fault->return_value,ts);
					bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

				}
				else{
					*counter = 0;
					description_of_fault->on = 0;
				}
			}
	}
}

