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
	int pid_to_use;
	int current_pid;
  int fault_count;
  struct maps_ebpf *maps;
	struct bpf_map *faults_specification;
	struct bpf_map *ring_buffer;
	struct bpf_map *leader;
	struct bpf_map *nodes_status;
	struct simplified_fault *fault;
};

struct majority_ctx{
	struct simplified_fault *fault;
	struct maps_ebpf *maps;
};

struct maps_ebpf{
	struct bpf_map *faults_specification;
	struct bpf_map *rb;
	struct bpf_map *auxiliary_info;
	struct bpf_map *nodes_status;
};

struct clear_conditions_ctx{
	int *conditions;
};
static inline int get_origin_pid(int pid, struct bpf_map *nodes_pid_translator);
static void process_counter(int stateinfo,int state_condition_value,int target_pid,int traced_pid,int fault_count,struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,struct bpf_map *auxiliary_info,struct bpf_map *nodes);
static inline int inject_fault(int faulttype,int pid, struct simplified_fault *fault,int pos,struct maps_ebpf *maps);
static inline __u64 process(struct bpf_map *map, int *pos,struct simplified_fault *fault , struct callback_ctx *data);

///////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////PID_TRANSLATION//////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

static inline int get_origin_pid(int pid, struct bpf_map *nodes_pid_translator){
   	int *old_pid = bpf_map_lookup_elem(nodes_pid_translator,&pid);

	int pid_to_use = 0;
	if(old_pid){
		pid_to_use = *old_pid;
		//bpf_printk("Translated pid, current_pid is %d, old_pid is %d \n",pid,pid_to_use);
	}else{
	   pid_to_use = pid;
	}

	return pid_to_use;
}
///////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////STATE_PROCESSING/////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

static inline int process_current_state(int state_key,int current_pid,int fault_count,int time_mode,
	struct bpf_map *relevant_state_info,struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,
	struct bpf_map *leader,struct bpf_map *nodes_status,struct bpf_map *nodes_translator){

	// if (state_key >=26)
	// 	bpf_printk("Got here from condition %d \n",state_key);
	//Get traced_pid from map

	//TODO: This is doubled, but adding an argument to a function in eBPF is pain, temporary fix
	int pid_to_use = get_origin_pid(current_pid, nodes_translator);
	//int *old_pid = bpf_map_lookup_elem(nodes_translator,&current_pid);

	// int pid_to_use = 0;
	// if(old_pid){
	// 	pid_to_use = *old_pid;
	// 	//bpf_printk("Translated pid, current_pid is %d, old_pid is %d \n",current_pid,pid_to_use);
	// }else{
	// 	//bpf_printk("No pid translation \n");
	// 	;
	// }

	// if (!pid_to_use){
	// 	pid_to_use = current_pid;
	// }

	struct info_key information_pid = {
		pid_to_use,
		state_key
	};

	struct info_state *current_state;

	current_state = bpf_map_lookup_elem(relevant_state_info,&information_pid);
	if (current_state){
		current_state->current_value++;
		int value = current_state->current_value;
		if(current_state->relevant_states){
			for (int i=0;i<fault_count;i++){
				if (current_state->relevant_states[i]){
					u64 relevant_value = current_state->relevant_states[i];
					if (relevant_value == value && relevant_value != 0){
						process_counter(state_key,value,pid_to_use,current_pid,fault_count,faults_specification,faults,rb,leader,nodes_status);
					}
					if(current_state->repeat && (value % relevant_value == 0)){
						process_counter(state_key,relevant_value,pid_to_use,current_pid,fault_count,faults_specification,faults,rb,leader,nodes_status);
					}
				}
			}

		}
		return 0;
	}
	//Time_mode means a fault has a condition based on time this means we have to process all syscalls
	if(time_mode){
		struct info_key information = {
			pid_to_use,
			TIME_FAULT
		};
		struct info_state *current_state;

		current_state = bpf_map_lookup_elem(relevant_state_info,&information);
		if (current_state){
			process_counter(TIME_FAULT,0,pid_to_use,current_pid,fault_count,faults_specification,faults,rb,leader,nodes_status);
		}
	}

	int *node_status = bpf_map_lookup_elem(nodes_status,&current_pid);

	//node_status value 2 means there is a fault to inject on this node
	if (node_status){
		if (*node_status == 2){
			if(time_mode)
				process_counter(TIME_FAULT,0,pid_to_use,current_pid,fault_count,faults_specification,faults,rb,leader,nodes_status);
			else
				process_counter(state_key,0,pid_to_use,current_pid,fault_count,faults_specification,faults,rb,leader,nodes_status);
			return 0;
		}
	}

	return 0;
}

static inline void process_counter(int stateinfo,int state_condition_value, int pid_to_use,int current_pid,int fault_count,
	struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,struct bpf_map *auxiliary_info,struct bpf_map *nodes_status){
	struct callback_ctx data;

	struct maps_ebpf maps;

	maps.faults_specification = faults_specification;
	maps.rb	 = rb;
	maps.auxiliary_info	 = auxiliary_info;
	maps.nodes_status = nodes_status;

	data.state_condition = stateinfo;
	data.state_condition_value = state_condition_value;
	data.pid_to_use = pid_to_use;
	data.current_pid = current_pid;
	data.fault_count = fault_count;
	data.maps = &maps;
	data.fault = NULL;
	bpf_for_each_map_elem(faults,process,&data,BPF_ANY);
}

static inline __u64 process(struct bpf_map *map, int *pos,struct simplified_fault *fault , struct callback_ctx *data){

	int fault_count = data->fault_count;
	if(*pos>=fault_count)
		return 1;


	if (fault){
		int fault_count = data->fault_count;
		int state_condition = data->state_condition;
		int pid_to_use = data->pid_to_use;
		int current_pid = data->current_pid;
		int state_condition_value = data->state_condition_value;

		int relevant_conditions = fault->relevant_conditions;
		int run = fault->run;

		if ((state_condition > STATE_PROPERTIES_COUNT+MAX_FUNCTIONS) || (state_condition < 0))
			return 1;

		//Check for fault termination
		if(fault->start_time && fault->duration){

			__u64 time_ns = bpf_ktime_get_ns();
			__u64 time_now = time_ns / 1000000;
			__u64 max_fault_time = fault->start_time + fault->duration;

			//If fault finished
			if(max_fault_time < time_now){

				int pid;
				if (fault->faulttype == NETWORK_ISOLATION ||fault->faulttype == DROP_PACKETS ||fault->faulttype == BLOCK_IPS)
					pid = fault->target_if_index;
				else
					pid = fault->pid;

				struct fault_key fault_to_inject = {
					pid,
					fault->faulttype
				};

				struct fault_description description_of_fault = {
				0,
				fault->occurrences,
				0,
				fault->return_value,
				0,
				fault->fault_nr
				};

				int error = bpf_map_update_elem(data->maps->faults_specification,&fault_to_inject,&description_of_fault,BPF_ANY);
				if (error)
					bpf_printk("Error of update is %d, faulttype->%d / value-> %d \n",error,fault->faulttype,1);

				bpf_printk("FAULT: %d FINISHED, TIME_ELAPSED: %d, TIME_NOW: %d, LASTED: %d\n",fault->fault_nr,max_fault_time,time_now,fault->duration);
				fault->start_time = 0;
				fault->done++;
			}
		}

		//If it is a majority fault we keep going
		if (fault->target == -2){
			;
		}
		//If it is not leave since we can not do anything in this pid
		else{
			if(fault->pid != pid_to_use){
				return 0;
			}
		}

		//Check if fault is done, if it is a majority we need to know if it is already done in a quorum

		if (fault->target == -2){
			if(fault->done >= fault->quorum_size){
				return 0;
			}
		}else{
			if(fault->done)
				return 0;
		}

		if (fault->initial.fault_type_conditions){
			int *conditions = fault->initial.fault_type_conditions;
			if (conditions[state_condition]){
				int condition_value = conditions[state_condition];
				if(state_condition_value > 0){
					if (!(fault->initial.conditions_match[state_condition])){
						//Needed because in the above function we do not know for what fault the relevant fault is
						if (condition_value == state_condition_value){
								bpf_printk("FAULT: %d, COND: %d, CURRENT_VALUE: %d, NEEDED: %d\n",*pos,state_condition,condition_value,state_condition_value);
								__sync_fetch_and_add(&(fault->initial.conditions_match[state_condition]),1);
								run+=1;
								fault->run = run;
							}
						}

				}
			}
		}

		int zero = 0;
		if (run >= relevant_conditions){
			bpf_printk("FAULT: %d, RUN: %d, RC: %d\n",fault->fault_nr,run,relevant_conditions);
				//TODO: implement this only works for process faults
			if (fault->target == -1){
				//TODO: inject fault on leader
			}
			//TODO: implement this only works for process faults
			else if (fault->target == -2){
				int pos_zero = 0;
				int *leader_pid_pointer = bpf_map_lookup_elem(data->maps->auxiliary_info,&pos_zero);

				int leader_pid = 0;
				if(leader_pid_pointer)
					leader_pid = *leader_pid_pointer;

				//10 IS TEMP it is basically MAX_NODES
				//Iterate through nodes and mark them as targets for faults
				for(int i = 0; i < 10 ;i++){

					int node_pos = i + 2;
					int *node_pid = bpf_map_lookup_elem(data->maps->auxiliary_info,&node_pos);

					if (node_pid ){
						//If it is leader skip
						if (*node_pid == leader_pid)
							continue;

						if(*node_pid !=0){
							inject_fault(fault->faulttype,*node_pid,fault,0,data->maps);
						}
					}else{
						break;
					}

				}


			}
			//Network faults are done with TC they have no pid, so pid is 0
			else if (fault->faulttype == NETWORK_ISOLATION ||fault->faulttype == DROP_PACKETS ||fault->faulttype == BLOCK_IPS){
				inject_fault(fault->faulttype,fault->target_if_index,fault,*pos,data->maps);
			}
			else{
				inject_fault(fault->faulttype,current_pid,fault,*pos,data->maps);
			}
		}

	}
	return 0;
}

static inline int inject_fault(int fault_type,int pid,struct simplified_fault *fault,int pos,struct maps_ebpf *maps){

	int pid_to_target = pid;
	int running_pid = bpf_get_current_pid_tgid() >> 32;

	if (fault){
		//If it is a fault to inject on a leader we use the leader_pid
		//TODO: This is no longer necessary since the pid_to_target needs to be the one here
		if (fault->target == -1){
			bpf_printk("Looking to inject fault in a leader \n");
			int zero = 0;
			int *leader_pointer = bpf_map_lookup_elem(maps->auxiliary_info,&zero);

			if(leader_pointer){
				if(*leader_pointer == pid_to_target){
					pid_to_target = *leader_pointer;
				}
			}
		}
		if (fault->target == -2){
			//bpf_printk("Looking to inject fault in a majority \n");
			if(fault->done >= fault->quorum_size){
				return 0;
			}
		}

		struct fault_description description_of_fault = {
			1,
			fault->occurrences,
			0,
			fault->return_value,
			0,
			fault->fault_nr
		};

		struct fault_key fault_to_inject = {
			pid_to_target,
			fault_type
		};

		if(fault_type == PROCESS_KILL || fault_type == PROCESS_STOP){

			if(running_pid != pid_to_target){
				if (fault->faults_injected_counter >= fault->quorum_size){
					return 0;
				}
				int fault_code = 2;
				int error = bpf_map_update_elem(maps->nodes_status,&pid_to_target,&fault_code,BPF_ANY);
				if (error)
					bpf_printk("Error of update is %d, running_pid->%d / fault_code-> %d \n",error,running_pid,fault_code);
				fault->faults_injected_counter+=1;
				return 0;
			}
			//Do this as early as possible for contention
			fault->done++;
			if (fault_type == PROCESS_KILL){
				bpf_printk("KILLING PID: %d\n", pid_to_target);
				__u64 time = bpf_ktime_get_ns();
				__u64 time_ms = time / 1000000;
				fault->start_time = time_ms;
				fault->timestamp = time;
				bpf_send_signal(9);
			}
			if (fault_type == PROCESS_STOP){
				bpf_printk("STOPPING PID: %d\n", pid_to_target);
				__u64 time = bpf_ktime_get_ns();
				__u64 time_ms = time / 1000000;
				fault->start_time = time_ms;
				fault->timestamp = time;
				//TODO: Change and confirm this works
				bpf_send_signal(19);
			}

			//Send message to user space to restart process
			struct event *e;
			e = bpf_ringbuf_reserve(maps->rb, sizeof(*e), 0);
			if (!e)
				return 0;

			e->type = fault_type;
			e->pid = pid_to_target;
			e->fault_nr = fault->fault_nr;

			//bpf_printk("Sent %d to userpace to pid %d for fault_nr %d\n",fault_type,e->pid,fault->fault_nr);
			bpf_ringbuf_submit(e, 0);

			int fault_code = 0;
			int error = bpf_map_update_elem(maps->nodes_status,&pid_to_target,&fault_code,BPF_ANY);
			if (error)
				bpf_printk("Error of update is %d, running_pid->%d / fault_code-> %d\n",error,running_pid,fault_code);


			//Reset run to 0, if in majority only if we did all faults already
			if (fault->target == -2){
				if(fault->done >= fault->quorum_size){
					fault->run = 0;
				}
			}
			else{
				fault->run = 0;
			}

		}else{
			bpf_printk("FAULT:%d READY, TYPE: %d, PID: %d\n",fault->fault_nr,fault_type,pid_to_target);
			__u64 time = bpf_ktime_get_ns();
			__u64 time_ms = time / 1000000;
			fault->start_time = time_ms;
			fault->timestamp = time;
			bpf_printk("Changed timestamp to %llu\n",fault->timestamp);
			int error = bpf_map_update_elem(maps->faults_specification,&fault_to_inject,&description_of_fault,BPF_ANY);
			if (error)
				bpf_printk("Error of update is %d, faulttype->%d / value-> %d\n",error,fault_type,1);

			fault->run = 0;

			if (!fault->duration)
				fault->done++;
		}

		if (fault->repeat){
			bpf_printk("REPEAT: ON\n");
			fault->done = 0;
			for (int i = 0; i< STATE_PROPERTIES_COUNT;i++){
				fault->initial.conditions_match[i] = 0;
			}
		}
		//bpf_printk("Cleared conditions \n");

		return 0;

	}

}

static inline void inject_override(int pid,int fault,struct pt_regs* ctx,int syscall_nr, struct bpf_map* faults_specification){
	struct fault_key fault_to_inject = {
		pid,
		fault,
	};
	//bpf_printk("Checking for pid %d and fault %d \n",pid,fault);
	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(faults_specification,&fault_to_inject);


	if (description_of_fault){
		//bpf_printk("Fault is ON occurrences is %d counter is %d \n",description_of_fault->occurences,description_of_fault->counter);
			if (description_of_fault->on){
				if (description_of_fault->counter < description_of_fault->occurences){
					description_of_fault->counter+=1;
					//u64 ts = bpf_ktime_get_ns();
					bpf_printk("INJECTED FAULT: %d, OCURRENCE: %d, RETURN VALUE %d\n",fault,description_of_fault->occurences,description_of_fault->return_value);
					bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

				}
				else if(description_of_fault->occurences == 0){
					//u64 ts = bpf_ktime_get_ns();
					bpf_printk("INJECTED FAULT: %d, RETURN VALUE %d\n",fault,description_of_fault->return_value);
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
