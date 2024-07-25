#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "faultinject.h"
#include "aux.h"
#include "fs.bpf.h"
#include "fs.h"
#include "faultinject.h"


struct callback_ctx {
	int state_condition;
	int state_condition_value;
	int traced_pid;
	int target_pid;
    int fault_count;
    struct maps_ebpf *maps;
	struct bpf_map *faults_specification;
	struct bpf_map *ring_buffer;
	struct bpf_map *leader;
	struct bpf_map *nodes_status;
};

struct maps_ebpf{
	struct bpf_map *faults_specification;
	struct bpf_map *rb;
	struct bpf_map *leader;
	struct bpf_map *nodes_status;
};

struct clear_conditions_ctx{
	int *conditions;
};

static void process_counter(int stateinfo,int state_condition_value,int target_pid,int traced_pid,int fault_count,struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,struct bpf_map *leader,struct bpf_map *nodes);
static void inject_fault(int faulttype,int pid,int syscall_nr, struct simplified_fault *fault,int pos,struct maps_ebpf *maps);
static __u64 process(struct bpf_map *map, int *pos,struct simplified_fault *fault , struct callback_ctx *data);



///////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////STATE_PROCESSING/////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

static int process_current_state(int state_key,int target_pid,int fault_count,int time_mode,
	struct bpf_map *relevant_state_info,struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,
	struct bpf_map *leader,struct bpf_map *nodes_status,struct bpf_map *nodes_translator){

	//TODO: Something wrong here
	//Get traced_pid from map
	int *check_pid = bpf_map_lookup_elem(nodes_translator,&target_pid);

	int traced_pid = 0;
	if(check_pid){
		traced_pid = *check_pid;
		//bpf_printk("Check pid is %d, target is %d \n",traced_pid,target_pid);
	}

	if (!traced_pid){
		traced_pid = target_pid;
	}

	struct info_key information_pid = {
		traced_pid,
		state_key
	};


	struct info_state *current_state;

	current_state = bpf_map_lookup_elem(relevant_state_info,&information_pid);

	if (current_state){
		//bpf_printk("Checking stuff in pid: %d\n",pid);
		current_state->current_value++;
		int value = current_state->current_value;
		if(current_state->relevant_states){
			for (int i=0;i<fault_count;i++){
				if (current_state->relevant_states[i]){
					u64 relevant_value = current_state->relevant_states[i];
					if (relevant_value == value && relevant_value != 0){

						bpf_printk("Found relevant value for property %d \n",state_key);
						process_counter(state_key,value,traced_pid,target_pid,fault_count,faults_specification,faults,rb,leader,nodes_status);
					}
					if(current_state->repeat && (value % relevant_value == 0)){
						bpf_printk("Found relevant value and repeating\n");
						process_counter(state_key,relevant_value,traced_pid,target_pid,fault_count,faults_specification,faults,rb,leader,nodes_status);
					}
					//bpf_printk("Skipped \n");
					}
				}

		}
	}
	if(time_mode){
		//bpf_printk("Time mode on \n");
		struct info_key information = {
			traced_pid,
			TIME_FAULT
		};
		struct info_state *current_state;

		//TEMP FIX FOR TESTING
		//process_counter(TIME_FAULT,0,pid,fault_count,faults_specification,faults,rb);

		current_state = bpf_map_lookup_elem(relevant_state_info,&information);
		if (current_state){
			process_counter(TIME_FAULT,0,traced_pid,target_pid,fault_count,faults_specification,faults,rb,leader,nodes_status);
		}
	}
	return 0;
}

static void process_counter(int stateinfo,int state_condition_value, int traced_pid,int target_pid,int fault_count,
	struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,struct bpf_map *leader,struct bpf_map *nodes_status){
	struct callback_ctx data;

	struct maps_ebpf maps;

	maps.faults_specification =faults_specification;
	maps.rb	 = rb;
	maps.leader	 =leader;
	maps.nodes_status =nodes_status;


	data.state_condition = stateinfo;
	data.state_condition_value = state_condition_value;
	data.traced_pid = traced_pid;
	data.target_pid = target_pid;
    data.fault_count = fault_count;
    data.maps = &maps;
    /*data.faults_specification = faults_specification;
	data.ring_buffer = rb;
	data.leader = leader;
	data.nodes_status = nodes_status;*/
	bpf_for_each_map_elem(faults,process,&data,BPF_ANY);
}

static  __u64 process(struct bpf_map *map, int *pos,struct simplified_fault *fault , struct callback_ctx *data){

    int fault_count = data->fault_count;
	if(*pos>=fault_count)
		return 1;
	/*struct bpf_map *faults_specification = data->faults_specification;
	struct bpf_map *rb = data->ring_buffer;
	struct bpf_map *leader = data->leader;
	struct bpf_map *nodes = data->nodes_status;*/
	int state_condition = data->state_condition;
	int traced_pid = data->traced_pid;
	int target_pid = data->target_pid;
	int state_condition_value = data->state_condition_value;
	int conditions[STATE_PROPERTIES_COUNT];

	int relevant_conditions = fault->relevant_conditions;

	//Get current state of run
	int run = fault->run;
	if (fault){

		if (fault->done)
			return 0;

		if (fault->initial.fault_type_conditions){
			int *conditions = fault->initial.fault_type_conditions;
            if ((state_condition > STATE_PROPERTIES_COUNT) || (state_condition < 0))
                return 1;
			if (conditions[state_condition]){
				int condition_value = conditions[state_condition];
				if(state_condition_value > 0){
					if (state_condition_value == condition_value && traced_pid == fault->pid){
                       // if ((state_condition > STATE_PROPERTIES_COUNT) || (state_condition < 0))
                       //     return 1;
					 	__sync_fetch_and_add(&(fault->initial.conditions_match[state_condition]),1);
						//bpf_printk("Changing to true property for fault %d in state key %d \n",*pos,state_condition);
                        //fault->initial.conditions_match[state_condition] = 1;
					}
				}
			}
		}

		//THIS SHOULD WORK SINCE WE ALWAYS GO OVER EVERY FAULT
		// for(int i = 0;i <STATE_PROPERTIES_COUNT;i++ ){
		if(state_condition>0 && state_condition<(STATE_PROPERTIES_COUNT+MAX_FUNCTIONS)){
			if (fault->initial.conditions_match[state_condition]){
				run+=1;
				fault->run = run;
				//bpf_printk("Incremented value in run %d \n",fault->initial.conditions_match[state_condition]);
			}

		}
		//	}

		//bpf_printk("Run is %d and rc %d \n",run,relevant_conditions);

		int zero = 0;
		if (run >= relevant_conditions){
			//bpf_printk("Fault nr %d done is %d and target is %d\n",fault->fault_nr,fault->done,fault->fault_target);
			if (!fault->done){
				fault->done = 1;
				int pid = 0;
				//TODO: implement this only works for process faults
				if (fault->fault_target == -1){
					bpf_printk("Calling fault on leader \n");
					//int leader_pid = bpf_map_lookup_elem(leader,&zero);
					//if(leader_pid){
					//
					//}
				}
				//TODO: implement this only works for process faults
				else if (fault->fault_target == -2){
					bpf_printk("Calling fault on majority \n");
					int *check_leader_pid = bpf_map_lookup_elem(data->maps->leader,&zero);
					int leader_pid = 0;
					if(check_leader_pid)
						leader_pid = *check_leader_pid;

					if(target_pid == leader_pid){
						fault->done = 0;
						bpf_printk("I am the leader therefore I can not call this fault leader_pid %d | target_pid %d\n",leader_pid,target_pid);
						return 0;
					}
					else{
						inject_fault(fault->faulttype,target_pid,0,fault,*pos,data->maps);
						return 1;
					}

				}
				else if (fault->faulttype == NETWORK_ISOLATION ||fault->faulttype == DROP_PACKETS ||fault->faulttype == BLOCK_IPS){
					bpf_printk("Calling network fault \n");
					inject_fault(fault->faulttype,0,0,fault,*pos,data->maps);
					return 1;
				}
				else{
					bpf_printk("Calling generic fault \n");
					inject_fault(fault->faulttype,target_pid,0,fault,*pos,data->maps);
					return 1;
				}
			}
		}

		if(fault->start_time){
			//bpf_printk("Start time is %d for fault %d \n",fault->start_time,fault->fault_nr);

			__u64 time_ns = bpf_ktime_get_ns();
			__u64 time_now = time_ns / 1000000;

			__u64 max_fault_time = fault->start_time+fault->duration;
			//Check if we are done with this fault
			if(max_fault_time < time_now){

				struct fault_key fault_to_inject = {
					fault->pid,
					fault->faulttype
				};

				struct fault_description description_of_fault = {
				0,
				fault->occurrences,
				0,
				fault->return_value,
				0
				};

				int error = bpf_map_update_elem(data->maps->faults_specification,&fault_to_inject,&description_of_fault,BPF_ANY);
				if (error)
					bpf_printk("Error of update is %d, faulttype->%d / value-> %d \n",error,fault->faulttype,1);

				bpf_printk("Fault %d is finished time_elapsed is %d and time_now is %d\n",fault->fault_nr,max_fault_time,time_now);
				fault->start_time = 0;
			}
		}

	}
	return 0;
}


static long clear_conditions(__u32 index, struct clear_conditions_ctx *ctx){

}

static void inject_fault(int fault_type,int pid,int syscall_nr,struct simplified_fault *fault,int pos,struct maps_ebpf *maps){

	int pid_to_target = pid;

	if (fault){
		if (fault->fault_target == -1){
			bpf_printk("Looking to inject fault in a leader \n");
			int zero = 0;
			int *leader_pointer = bpf_map_lookup_elem(maps->leader,&zero);

			if(leader_pointer){
				if(*leader_pointer == pid_to_target){
					pid_to_target = *leader_pointer;
				}
			}

		}

		if (fault->fault_target == -2){
			bpf_printk("Looking to inject fault in a majority \n");
			int zero = 0;
			int *node_status = bpf_map_lookup_elem(maps->nodes_status,&pid_to_target);

			if (node_status){
				if (*node_status){
					fault->done = 0;
					for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
						fault->initial.conditions_match[i] = 0;
					}
					return;
				}
			}

		}

		struct fault_description description_of_fault = {
			1,
			fault->occurrences,
			0,
			fault->return_value,
			syscall_nr
		};

		struct fault_key fault_to_inject = {
			pid_to_target,
			fault_type
		};

		bpf_printk("Fault nr:%d with fault_type %d at pid %d will occurr %d with return value %d \n",fault->fault_nr,pid,fault->occurrences,fault->return_value);

		if(fault_type == PROCESS_KILL || fault_type == PROCESS_STOP){
			struct event *e;
			e = bpf_ringbuf_reserve(maps->rb, sizeof(*e), 0);
			if (!e)
				return;

			e->type = fault_type;
			e->pid = pid_to_target;
			e->fault_nr = fault->fault_nr;
			bpf_printk("Sent %d to userpace to pid %d",fault_type,pid_to_target);
			bpf_ringbuf_submit(e, 0);
			fault->run = 0;

		}else{
			//bpf_printk("Fault is ready to run \n");
			int error = bpf_map_update_elem(maps->faults_specification,&fault_to_inject,&description_of_fault,BPF_ANY);
			if (error)
				bpf_printk("Error of update is %d, faulttype->%d / value-> %d \n",error,fault_type,1);
			fault->done = 1;
			fault->run = 0;
			//bpf_printk("Resseting done and run \n");

			//Assign start time, to later check if duration is done
			__u64 time_ns = bpf_ktime_get_ns();
			__u64 time_ms = time_ns / 1000000;
			fault->start_time = time_ms;
		}

		fault->faults_injected_counter++;
		if (fault->repeat){
			bpf_printk("Repeat on \n");
			fault->done = 0;
		}

		for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
			fault->initial.conditions_match[i] = 0;
		}

		// struct clear_conditions_ctx ctx = {
		// 	.conditions->initial.conditions_match
		// };

		// bpf_loop(STATE_PROPERTIES_COUNT,clear_conditions,&ctx,0);


	}

}

static void inject_override(int pid,int fault,struct pt_regs* ctx,int syscall_nr,struct bpf_map* faults_specification){
	struct fault_key fault_to_inject = {
		pid,
		fault,
	};
	//bpf_printk("Checking for pid %d and fault %d \n",pid,fault);
	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(faults_specification,&fault_to_inject);


	if (description_of_fault){
		//bpf_printk("Fault is ON \n");
			if (description_of_fault->on){
				if (description_of_fault->counter < description_of_fault->occurences){
					description_of_fault->counter+=1;
					u64 ts = bpf_ktime_get_ns();
					bpf_printk("Injected fault %d ocurrence: %d with return value %d at ts %u \n",fault,description_of_fault->counter,description_of_fault->return_value,ts);
					bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

				}
				else if(description_of_fault->occurences == 0){
					u64 ts = bpf_ktime_get_ns();
					bpf_printk("Injected fault %d with return value %d at ts %u \n",fault,description_of_fault->return_value,ts);
					description_of_fault->on = 0;
					bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

				}
				else{
					description_of_fault->counter = 0;
					description_of_fault->on = 0;
				}
			}
	}
}


//Not usable because of verifier
// static void process_fd_syscall(struct pt_regs *ctx,struct sys_info *sys_info,struct bpf_map *relevant_state_info,struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,struct bpf_map *files,struct bpf_map *relevant_fd){

// 	__u64 pid_tgid = bpf_get_current_pid_tgid();
// 	__u32 pid = pid_tgid >> 32;
// 	__u32 tid = (__u32)pid_tgid;


// 	FileFDKey fdkey = {};
// 	int fd;
// 	int process_fd = 1;

// 	fd = sys_info->fd;

// 	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(relevant_fd,&pid);

// 	if(fdrelevant){
// 		for (int i=0;i<fdrelevant->size;i++){
// 			if(i>MAX_RELEVANT_FILES)
// 				break;
// 			__u64 relevant_fd = fdrelevant->fds[i];
// 			if(relevant_fd == fd){
// 				process_fd = 0;
// 				process_current_state(sys_info->file_specific_code,pid,sys_info->fault_count,sys_info->time_only,relevant_state_info,faults_specification,faults,rb);
// 				inject_override(pid,sys_info->file_specific_code,(struct pt_regs *) ctx,0,faults_specification);
// 				break;
// 			}
// 		}
// 	}else{
// 		process_fd = 0;
// 	}

// 	if (fd > 0 && process_fd){
// 		struct file *file = get_file_from_fd(fd);

// 		if(!file){
// 			//bpf_printk("File not found \n");
// 			return;
// 		}

// 		struct path path = get_path_from_file(file);

// 		struct inode *inode = get_inode_from_path(&path);

// 		if (!inode) return;
// 		if (get_file_tag(&fdkey, inode)) return;

// 		EventPath event_path = {};
// 		event_path.etype = 0;
// 		event_path.n_ref = 0;
// 		event_path.index = 0;
// 		event_path.cpu = bpf_get_smp_processor_id();

// 		FileInfo fi = {};

// 		bpf_probe_read(&fi.file_type, sizeof(fi.file_type), &inode->i_mode);

// 		if (get_file_path(&path, &event_path, &fi) != 0) return;

// 		struct info_key info_key = {
// 			pid,
// 			sys_info->file_specific_code
// 		};
// 		struct file_info_simple *file_open = bpf_map_lookup_elem(files,&info_key);
// 		if(file_open){
// 			//bpf_printk("Comparing %s and %s \n",&(fi.filename[fi.offset]),file_open->filename);
// 			if(string_contains(file_open,&(fi.filename[fi.offset]),fi.offset)){
// 				struct relevant_fds *fds = bpf_map_lookup_elem(relevant_fd,&pid);
// 				if(fds){
// 					u64 position = fds->size;
// 					if(position < MAX_RELEVANT_FILES){
// 						bpf_printk("Adding fd %d to pos %d",fd,fds->size);
// 						fds->fds[position] = fd;
// 						fds->size = fds->size + 1;
// 					}
// 				}else{
// 					bpf_printk("This should not happen, main should init the structures \n");
// 				}
// 				process_current_state(sys_info->file_specific_code,pid,sys_info->fault_count,sys_info->time_only,relevant_state_info,faults_specification,faults,rb);
// 				inject_override(pid,sys_info->file_specific_code,(struct pt_regs *) ctx,0,faults_specification);

// 			}
// 		}
// 	}

// 	process_current_state(sys_info->general_syscall_code,pid,sys_info->fault_count,sys_info->time_only,relevant_state_info,faults_specification,faults,rb);
// 	inject_override(pid,sys_info->fault_code,(struct pt_regs *) ctx,0,faults_specification);

// }
