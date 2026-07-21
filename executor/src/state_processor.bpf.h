#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fault_inject.h"
#include "bpf_shared.h"

///////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////FILE_HELPERS/////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

static inline struct file* get_file_from_fd(int32_t fd)
{
    if (fd < 0) return NULL;

    struct task_struct *curr_task = (struct task_struct *) bpf_get_current_task();
    if (!curr_task) return NULL;

    struct files_struct *files = NULL;
    bpf_probe_read(&files, sizeof(files), &curr_task->files);
    if (!files) return NULL;

    struct fdtable *fdtable = NULL;
    bpf_probe_read(&fdtable, sizeof(fdtable), &files->fdt);
    if (!fdtable) return NULL;

    struct file **fileptr = NULL;
    bpf_probe_read(&fileptr, sizeof(fileptr), &fdtable->fd);
    if (!fileptr) return NULL;

    struct file *file = NULL;
    bpf_probe_read(&file, sizeof(file), &fileptr[fd]);

    return file;
}

static inline struct path get_path_from_file(struct file *file) {
    struct path path;
    bpf_probe_read(&path, sizeof(path), (const void*)&file->f_path);
    return path;
}

static inline struct inode* get_inode_from_path(struct path *path ) {
    struct inode *inode;
    struct dentry *dentry = path->dentry;
    if(!dentry) return NULL;
    bpf_probe_read(&inode, sizeof(inode), &dentry->d_inode);
    return inode;
}

static inline int get_file_tag(FileFDKey *file_tag, struct inode *inode) {
    struct super_block	*i_sb = NULL;
    bpf_probe_read(&i_sb, sizeof(struct i_sb*), &inode->i_sb);
    if (!i_sb) return -1;

    bpf_probe_read(&file_tag->ino, sizeof(file_tag->ino), &inode->i_ino);
    bpf_probe_read(&file_tag->dev, sizeof(file_tag->dev), &i_sb->s_dev);

    return 0;
}

static inline struct dentry* get_dentry_from_path(struct path *path ) {
    return path->dentry;
}

static inline struct vfsmount* get_mnt_from_path(struct path *path ) {
    return path->mnt;
}

static inline struct mount* get_real_mount(struct vfsmount *vfs_mnt) {
    return container_of(vfs_mnt, struct mount, mnt);
}

static inline struct mount* get_mount_parent(struct mount *mnt) {
    struct mount *mount_p;
    bpf_probe_read(&mount_p, sizeof(struct mount *), &mnt->mnt_parent);
    return mount_p;
}

static inline int get_file_path(struct path *path, FileInfo *fi) {
    u32 i, len, offset, last_position;
    char slashchar = '/', nulchar = '\0';
    struct dentry *dentry, *parent, *mnt_root;
    struct vfsmount *vfs_mnt;
    struct mount *real_mount, *mount_parent;
    struct qstr d_name;
    int flag = 0;
    dentry = get_dentry_from_path(path);
    if (!dentry) return 1;
    vfs_mnt = get_mnt_from_path(path);
    if (!vfs_mnt) return 1;
    real_mount = get_real_mount(vfs_mnt);
    if (!real_mount) return 1;
    mount_parent = get_mount_parent(real_mount);
    if (!mount_parent) return 1;
    offset = last_position = MAX_FILE_OFFSET;
    #pragma unroll
    for (i = 0; i < MAX_JUMPS; i++) {
        // get parent dentry
        bpf_probe_read_kernel((void *) &parent, sizeof(parent), (void*)&(dentry->d_parent));
        if (!parent) break;
        // get mount root dentry
        bpf_probe_read_kernel((void *) &mnt_root, sizeof(mnt_root), (void*)&(vfs_mnt->mnt_root));
        if (!mnt_root) break;
        // stop if dentry equals parent or mount root
        if (dentry == mnt_root || dentry == parent)  {
            // find final root through the mount point
            if (dentry == mnt_root && real_mount != mount_parent) {
                bpf_probe_read(&dentry, sizeof(dentry), &real_mount->mnt_mountpoint);
                bpf_probe_read(&real_mount, sizeof(real_mount), &real_mount->mnt_parent);
                bpf_probe_read(&mount_parent, sizeof(mount_parent), &real_mount->mnt_parent);
                vfs_mnt = &real_mount->mnt;
                continue;
            }
            // reached end -> stop
            flag=1;
            if (i>0) offset++;
        }
        // get file name length
        bpf_probe_read_kernel(&d_name, sizeof(d_name), (const void*)&(dentry->d_name));
        len = d_name.len + 1;
        if (len >= SUB_STR_MAX) len = SUB_STR_MAX-1;
        len = len & (SUB_STR_MAX-1);
        // calculate new position to write
        offset = (offset - len);
        if (offset > last_position) break;
        // copy file name into buffer
        len = (len-1) &  (MAX_FILE_OFFSET - 1);
        int err = bpf_probe_read_kernel(&(fi->filename[offset & (MAX_FILE_OFFSET-1)]), len, (void *) d_name.name);
        if (err < 0){
            break;
            bpf_printk("Failed to read filename from kernel with err:%d\n",err);
        }
        if (flag) {
            last_position = offset;
            break;
        }
        // Add a slash character
        last_position--;
        bpf_probe_read_kernel(&(fi->filename[last_position & (FILENAME_MAX_SIZE-1)]), 1, &slashchar);
        last_position = offset;
        // get parent dentry name
        dentry = parent;
    }
    fi->offset = last_position;
    if (last_position == MAX_FILE_OFFSET) fi->size = MAX_FILE_OFFSET - last_position;
    else fi->size = MAX_FILE_OFFSET - last_position - 1;
    return 0;
}

static inline bool string_contains(char *str1,char *str2,int size) {
    const char comparand[32];
    const char comparand2[32];
    bpf_probe_read(&comparand, sizeof(comparand), str1);
    bpf_probe_read(&comparand2, sizeof(comparand2), str2);

    //-1 because of the null terminator
    int str_len = size;
    int count = 0;
    #pragma unroll
    for (int i = 0; i < 32; ++i){
        if (comparand[count] == comparand2[i] ){
            count++;
            if(str_len == count){
                return true;
            }
            continue;
        }else{
            count = 0;
        }

    }
    return false;
}

struct callback_ctx {
	int state_condition;
	int state_condition_value;
	int pid_to_use;
	int current_pid;
    int fault_count;
    int fault_key;
    struct maps_ebpf *maps;
	struct simplified_fault *fault;
	struct pt_regs *ctx;
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
	struct bpf_map *faults;
};

struct clear_conditions_ctx{
	int *conditions;
};
static __always_inline int get_origin_pid(int pid, struct bpf_map *nodes_pid_translator);
//static inline int test_new_process_current_state(int state_key,int current_pid,int fault_count,int mode,struct maps *maps);
static __always_inline void process_counter(int stateinfo,int state_condition_value,int target_pid,int traced_pid,int fault_count,int fault_key,struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,struct bpf_map *auxiliary_info,struct bpf_map *nodes,struct pt_regs *ctx);
static __always_inline int inject_fault(int fault_key,int pid, struct simplified_fault *fault,int pos,struct maps_ebpf *maps,struct pt_regs *ctx);
static inline __u64 process(struct bpf_map *map, int *pos,struct simplified_fault *fault , struct callback_ctx *data);
static __always_inline void satisfy_fault_deps(struct bpf_map *faults, int fired_nr);

///////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////PID_TRANSLATION//////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

static __always_inline int get_origin_pid(int pid, struct bpf_map *nodes_pid_translator){
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


static __always_inline int process_current_state(int state_key,int fault_key,int current_pid,int fault_count,int mode, struct bpf_map *relevant_state_info,struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb, struct bpf_map *leader,struct bpf_map *nodes_status,struct bpf_map *nodes_translator,struct pt_regs *ctx){

	//TODO: This is doubled, but adding an argument to a function in eBPF is pain, temporary fix
	int pid_to_use = get_origin_pid(current_pid, nodes_translator);

	struct info_key information_pid = {
		pid_to_use,
		state_key
	};
	struct info_state *current_state;

	//Checks the schedule info for a specific state_key (e.g. write invocations), and checks if we a condition for a fault triggered
	current_state = bpf_map_lookup_elem(relevant_state_info,&information_pid);
	if (current_state){
		current_state->current_value++;
		int value = current_state->current_value;
		if(current_state->relevant_states){
			for (int i=0;i<fault_count;i++){
				if (current_state->relevant_states[i]){
					u64 relevant_value = current_state->relevant_states[i];
					if ((value % relevant_value == 0) && relevant_value != 0){
					   //For all the faults which leverage this condition we sheck if the rest of the conditions are already triggered
					   process_counter(state_key,relevant_value,pid_to_use,current_pid,fault_count,fault_key,faults_specification,faults,rb,leader,nodes_status,ctx);
					}
				}
			}

		}
		return 0;
	}
	//Time_mode means a fault has a condition based on time this means we have to process all syscalls
	if(mode & TIME_DEP){
		struct info_key information = {
			pid_to_use,
			TIME_STATE
		};
		struct info_state *current_state;

		current_state = bpf_map_lookup_elem(relevant_state_info,&information);
		if (current_state){
			process_counter(TIME_STATE,0,pid_to_use,current_pid,fault_count,fault_key,faults_specification,faults,rb,leader,nodes_status,ctx);
		}
	}

	if(mode & FAULT_DEP){
		process_counter(0,0,pid_to_use,current_pid,fault_count,fault_key,faults_specification,faults,rb,leader,nodes_status,ctx);
	}

	//This checks if a condition for this node was triggered by another node, relevant when traced is not equal to target in the schedule
	int *node_status = bpf_map_lookup_elem(nodes_status,&current_pid);

	//node_status value 2 means there is a fault to inject on this node
	if (node_status){
		if (*node_status == 2){
			if(mode & TIME_DEP)
				process_counter(TIME_STATE,0,pid_to_use,current_pid,fault_count,fault_key,faults_specification,faults,rb,leader,nodes_status,ctx);
			else
				process_counter(state_key,0,pid_to_use,current_pid,fault_count,fault_key,faults_specification,faults,rb,leader,nodes_status,ctx);
			return 0;
		}
	}

	return 0;
}

static __always_inline void process_counter(int stateinfo,int state_condition_value, int pid_to_use,int current_pid,int fault_count,int fault_key,
	struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb,struct bpf_map *auxiliary_info,struct bpf_map *nodes_status,struct pt_regs *ctx){
	struct callback_ctx data;
	struct maps_ebpf maps;

	//Contains the ebpf maps we leverage
	maps.faults_specification = faults_specification;
	maps.rb	= rb;
	maps.auxiliary_info	 = auxiliary_info;
	maps.nodes_status = nodes_status;
	maps.faults = faults;

	//Contains the auxiliary data to check if we need to inject a fault
	data.state_condition = stateinfo;
	data.state_condition_value = state_condition_value;
	//This is the pid which was used as key for all the mappings
	data.pid_to_use = pid_to_use;
	//This is the pid which called the a probe
	data.current_pid = current_pid;
	data.fault_count = fault_count;
	data.fault_key = fault_key;
	data.maps = &maps;
	data.fault = NULL;
	data.ctx = ctx;
	bpf_for_each_map_elem(faults,process,&data,BPF_ANY);
}

static inline __u64 process(struct bpf_map *map, int *pos,struct simplified_fault *fault , struct callback_ctx *data){

	int fault_count = data->fault_count;
	if(*pos>=fault_count)
		return 1;

	if (fault){
		int fault_count = data->fault_count;
		int fault_key = data->fault_key;
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
				//In network faults the pid is the index numbero of the network device
				if (fault->fault_type == NETWORK_ISOLATION ||fault->fault_type == DROP_PACKETS ||fault->fault_type == BLOCK_IPS)
					pid = fault->target_if_index;
				else
					pid = fault->pid;

				struct fault_key fault_to_inject = {
					pid,
					fault->fault_type
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
					bpf_printk("Error of update is %d, fault_type->%d / value-> %d \n",error,fault->fault_type,1);

				fault->start_time = 0;
			}
		}

		//If it is a majority fault we keep going
		// if (fault->target == -2){
		// 	;
		// }
		//If it is not leave since we can not do anything in this pid
		// else{
		// 	if(fault->pid != pid_to_use){
		// 	    bpf_printk("Different pid in fault: %d and pid: %d\n",fault->pid,pid_to_use);
		// 		return 0;
		// 	}
		// }

		//Check if fault is done, if it is a majority we need to know if it was already done for a quorum
		if (fault->target == -2){
			if(fault->done >= fault->quorum_size){
				return 0;
			}
		}else{
			if(fault->done >= fault->occurrences){
				return 0;
			}
		}

		//Check the conditions for a fault, if run == relevant_conditions we are ready
		if (fault->initial.fault_type_conditions){
			int *conditions = fault->initial.fault_type_conditions;
			if (conditions[state_condition]){
				int condition_value = conditions[state_condition];
				int time = conditions[TIME_STATE];
				int time_true = 1;
				if (time){
				    time_true = fault->initial.conditions_match[TIME_STATE];
				}
				//If we use time as a condition, the rest of the conditions can only be triggered after it
				if (time_true){
    				if(state_condition_value > 0){
    					if (!(fault->initial.conditions_match[state_condition])){
    						//Needed because in the above function we do not know for what fault the relevant value is
    						if (condition_value == state_condition_value){
                                bpf_printk("EXECUTOR: UPDATING STATE \n");
								__sync_fetch_and_add(&(fault->initial.conditions_match[state_condition]),1);
								run+=1;
								fault->run = run;
    							}
    						}

    				}
				}else{
					//bpf_printk("Time is not set to true\n");
				}
			}
		}

		#pragma unroll
		for (int k = 0; k < MAX_FAULT_DEPS; k++){
			if (fault->initial.dependency_fault_nrs[k] == -1)
				break;
			if (fault->initial.dependency_satisfied[k])
				continue;
			int dep_nr = fault->initial.dependency_fault_nrs[k];
			struct simplified_fault *dep = bpf_map_lookup_elem(map, &dep_nr);
			if (dep && (dep->start_time > 0 || dep->done > 0)){
				fault->initial.dependency_satisfied[k] = 1;
				run++;
				fault->run = run;
			}
		}

		int zero = 0;
		if (run >= relevant_conditions){
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
				for(int i = 0; i < MAX_NODES ;i++){

					int node_pos = i + 2;
					int *node_pid = bpf_map_lookup_elem(data->maps->auxiliary_info,&node_pos);

					if (node_pid){
						//If it is leader skip
						if (*node_pid == leader_pid)
							continue;

						if(*node_pid !=0){
							inject_fault(fault_key,*node_pid,fault,0,data->maps,data->ctx);
						}
					}else{
						break;
					}

				}
			}
			//Network faults are done with TC they have no pid, so pid is 0
			else if (fault->fault_type == NETWORK_ISOLATION ||fault->fault_type == DROP_PACKETS ||fault->fault_type == BLOCK_IPS){
				inject_fault(fault_key,fault->target_if_index,fault,*pos,data->maps,data->ctx);
			}
			else{
				inject_fault(fault_key,fault->pid,fault,*pos,data->maps,data->ctx);
			}
		}

	}
	return 0;
}

static __always_inline void satisfy_fault_deps(struct bpf_map *faults, int fired_nr){
	#pragma unroll
	for (int d = 0; d < MAX_FAULTS; d++){
		int d_idx = d;
		struct simplified_fault *df = bpf_map_lookup_elem(faults, &d_idx);
		if (!df || df->done >= df->occurrences) continue;
		if (df->initial.dependency_fault_nrs[0] == fired_nr && !df->initial.dependency_satisfied[0])
			{ df->initial.dependency_satisfied[0] = 1; df->run++; }
		if (df->initial.dependency_fault_nrs[1] == fired_nr && !df->initial.dependency_satisfied[1])
			{ df->initial.dependency_satisfied[1] = 1; df->run++; }
		if (df->initial.dependency_fault_nrs[2] == fired_nr && !df->initial.dependency_satisfied[2])
			{ df->initial.dependency_satisfied[2] = 1; df->run++; }
		if (df->initial.dependency_fault_nrs[3] == fired_nr && !df->initial.dependency_satisfied[3])
			{ df->initial.dependency_satisfied[3] = 1; df->run++; }
	}
}

static __always_inline int inject_fault(int fault_key,int current_pid,struct simplified_fault *fault,int pos,struct maps_ebpf *maps,struct pt_regs *ctx){

	int pid_to_target = current_pid;
	int running_pid = bpf_get_current_pid_tgid() >> 32;
	int fault_fired = 0;

	if (fault){
		//If it is a fault to inject on a leader we use the leader_pid
		//TODO: This is no longer necessary since the pid_to_target needs to be the one here
		if (fault->target == -1){
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


		if(fault->fault_type == PROCESS_KILL || fault->fault_type == PROCESS_STOP){

		    //bpf_printk("RUNNING_PID:%d, TARGET_PID:%d \n",running_pid,pid_to_target);
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
			if (fault->fault_type == PROCESS_KILL){
			    fault->done++;
				bpf_printk("FAULT:%d INJECTED PROCESS_KILL, PID:%d, OCCURRENCES:%d/%d\n",fault->fault_nr,pid_to_target,fault->done,fault->occurrences);
				bpf_send_signal(9);
				__u64 time = bpf_ktime_get_ns();
				__u64 time_ms = time / 1000000;
				fault->start_time = time_ms;
				fault->timestamp = time;
			}
			if (fault->fault_type == PROCESS_STOP){
			    fault->done++;
				bpf_printk("FAULT:%d INJECTED PROCESS_PAUSE, PID:%d, OCCURRENCES:%d/%d\n",fault->fault_nr,pid_to_target,fault->done,fault->occurrences);
				bpf_send_signal(19);
				__u64 time = bpf_ktime_get_ns();
				__u64 time_ms = time / 1000000;
				fault->start_time = time_ms;
				fault->timestamp = time;
				//TODO: Change and confirm this works
			}		//For system calls and network faults

			//Send message to user space to restart process
			struct event *e;
			e = bpf_ringbuf_reserve(maps->rb, sizeof(*e), 0);
			if (!e)
				return 0;

			e->type = fault->fault_type;
			e->pid = pid_to_target;
			e->fault_nr = fault->fault_nr;

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
			fault_fired = 1;

		}else if (fault->fault_type == CLEAR_CACHE){
		    fault->done++;
		    bpf_printk("FAULT:%d INJECTED CLEAR_CACHE, PID:%d, OCCURRENCES:%d/%d\n",fault->fault_nr,pid_to_target,fault->done,fault->occurrences);
			struct event *e;
			e = bpf_ringbuf_reserve(maps->rb, sizeof(*e), 0);
			if (!e)
				return 0;

			e->type = fault->fault_type;
			e->pid = pid_to_target;
			e->fault_nr = fault->fault_nr;

			bpf_ringbuf_submit(e, 0);
			fault_fired = 1;
		}
		else if (fault->fault_type == TORN_SEQ){
		    fault->done++;
		    bpf_printk("FAULT:%d INJECTED TORN_SEQ, PID:%d, OCCURRENCES:%d/%d\n",fault->fault_nr,pid_to_target,fault->done,fault->occurrences);
			struct event *e;
			e = bpf_ringbuf_reserve(maps->rb, sizeof(*e), 0);
			if (!e)
				return 0;

			e->type = fault->fault_type;
			e->pid = pid_to_target;
			e->fault_nr = fault->fault_nr;

			bpf_ringbuf_submit(e, 0);
			fault_fired = 1;
		}
		else if (fault->fault_type == TORN_OP){
		    fault->done++;
		    bpf_printk("FAULT:%d INJECTED TORN_OP, PID:%d, OCCURRENCES:%d/%d\n",fault->fault_nr,pid_to_target,fault->done,fault->occurrences);
			struct event *e;
			e = bpf_ringbuf_reserve(maps->rb, sizeof(*e), 0);
			if (!e)
				return 0;

			e->type = fault->fault_type;
			e->pid = pid_to_target;
			e->fault_nr = fault->fault_nr;

			bpf_ringbuf_submit(e, 0);
			fault_fired = 1;
		}
		else if (fault->fault_type == CRASH_FS){
		    fault->done++;
		    bpf_printk("FAULT:%d INJECTED CRASH_FS, PID:%d, OCCURRENCES:%d/%d\n",fault->fault_nr,pid_to_target,fault->done,fault->occurrences);
			struct event *e;
			e = bpf_ringbuf_reserve(maps->rb, sizeof(*e), 0);
			if (!e)
				return 0;

			e->type = fault->fault_type;
			e->pid = pid_to_target;
			e->fault_nr = fault->fault_nr;

			bpf_ringbuf_submit(e, 0);
			fault_fired = 1;

		//Network Faults
		}else if (fault->fault_type == NETWORK_ISOLATION || fault->fault_type == DROP_PACKETS || fault->fault_type == BLOCK_IPS){

		    fault->done++;
 			bpf_printk("FAULT:%d INJECTED TYPE:%d, PID:%d, OCCURRENCES:%d/%d\n",fault->fault_nr,fault->fault_type,pid_to_target,fault->done,fault->occurrences);
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
    			fault->fault_type
    		};
            __u64 time = bpf_ktime_get_ns();
			__u64 time_ms = time / 1000000;
			fault->start_time = time_ms;
			fault->timestamp = time;
			int error = bpf_map_update_elem(maps->faults_specification,&fault_to_inject,&description_of_fault,BPF_ANY);
			if (error) bpf_printk("Error of update is %d, fault_type->%d / value-> %d\n",error,fault->fault_type,1);
			fault_fired = 1;

			fault->run = 0;

		//System calls
		}else{
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
    		if (ctx && (fault_key == fault->fault_type)){
    			bpf_printk("FAULT:%d INJECTED TYPE:%d, PID:%d, RETURN VALUE:%d, OCCURRENCES:%d/%d\n",fault->fault_nr,fault->fault_type,pid_to_target,fault->return_value,fault->done+1,fault->occurrences);
    			bpf_override_return(ctx, fault->return_value);
    			fault_fired = 1;
    		}
    		else{
    		    return 0;
    		}
			fault->run = 0;
			fault->done++;
		}

		if (fault_fired && maps->faults)
			satisfy_fault_deps(maps->faults, fault->fault_nr);

		for (int i = 0; i< STATE_PROPERTIES_COUNT+MAX_FUNCTIONS;i++){
			fault->initial.conditions_match[i] = 0;
		}
		for (int i = 0; i < MAX_FAULT_DEPS; i++){
			fault->initial.dependency_satisfied[i] = 0;
		}

		return 0;

	}

}
