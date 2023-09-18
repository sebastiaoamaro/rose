// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "faultinject.h"
#include "aux.h"
#include "fs.bpf.h"
#include "fs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct fault_key);
	__type(value, struct fault_description);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faulttype SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct info_key);
	__type(value, struct info_state);
	 __uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_state_info SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, struct file_info_simple);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_fd SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} active_write_fd SEC(".maps");

const volatile int fault_count = 0;

static u64 writes_blocked = 0;
static u64 reads_blocked = 0;
static u64 threads_blocked = 0;
static u64 writes_file_blocked = 0;
static u64 writes_ret_overrun = 0;
static u64 opens_blocked = 0;
static u64 mkdir_blocked = 0;
static u64 newfstatat_blocked = 0;

static inline int process_current_state(int state_key, int type, int pid){

	struct info_key information = {
		pid,
		state_key
	};

	struct info_state *current_state;

	current_state = bpf_map_lookup_elem(&relevant_state_info,&information);
	
	if (current_state){
		//bpf_printk("Found write in pid %d \n",pid);

		current_state->current_value++;
		u64 value = current_state->current_value;
		if(current_state->relevant_states){
			for (int i=0;i<fault_count;i++){
				if (current_state->relevant_states[i]){
					u64 relevant_value = current_state->relevant_states[i];
					if (relevant_value == value && relevant_value != 0){

						struct event *e;

						/* reserve sample from BPF ringbuf */
						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
						if (!e)
							return 0;

						e->type = type;
						e->pid = pid;
						e->state_condition = value;
						bpf_ringbuf_submit(e, 0);
						return 0;
					}
					if(current_state->repeat && (value % relevant_value == 0)){
						struct event *e;

						/* reserve sample from BPF ringbuf */
						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
						if (!e)
							return 0;

						e->type = type;
						e->pid = pid;
						e->state_condition = relevant_value;
						bpf_ringbuf_submit(e, 0);
						return 0;
					}
					//bpf_printk("Skipped \n");
					}
					return 0;
				}
				
		}
	}
}


SEC("ksyscall/clone")
int BPF_KSYSCALL(clone,int flags)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

    int THREAD_FLAG = 0x10000;


	if (!(flags & THREAD_FLAG)){
		return 0;
	}

	// bpf_probe_read_kernel(&clone_flags,sizeof(clone_flags),clone_flags_ptr);
	// bpf_printk("param_flags is %x \n",flag_thread);
	// if (pid == 74705)
	//bpf_printk("Tid is %u and pid is %u \n",tid,pid);

	struct fault_key fault_to_inject = {
		pid,
		CLONE,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);


	if (description_of_fault){
		if (description_of_fault->on){
			if (threads_blocked < description_of_fault->occurences){
				threads_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else if(description_of_fault->occurences == 0){
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

			}
			else{
				threads_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(THREADS_CREATED,THREAD,pid);

	return 0;
}

SEC("ksyscall/clone3")
int BPF_KSYSCALL(clone3,struct clone_args *cl_args)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

    int THREAD_FLAG = 0x00010000;

	__u64 clone_flags;

	struct clone_args clone_args_new;

	bpf_probe_read_user(&clone_args_new, sizeof(clone_args_new), cl_args);

	//bpf_printk("A thread was created using clone3 and flags are is %u and result of & is %x \n",clone_args_new.flags,(clone_args_new.flags & THREAD_FLAG));
	if (!(clone_args_new.flags & THREAD_FLAG)){
		return 0;
	}

	// bpf_probe_read_kernel(&clone_flags,sizeof(clone_flags),clone_flags_ptr);
	// bpf_printk("param_flags is %x \n",flag_thread);
	// if (pid == 74705)
	//bpf_printk("Tid is %u and pid is %u \n",tid,pid);

	struct fault_key fault_to_inject = {
		pid,
		CLONE,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);


	if (description_of_fault){
		if (description_of_fault->on){
			if (threads_blocked < description_of_fault->occurences){
				threads_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else if(description_of_fault->occurences == 0){
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

			}
			else{
				threads_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(THREADS_CREATED,THREAD,pid);

	return 0;
}

SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(__x64_sys_write,struct pt_regs *regs)
{

	// bpf_printk("%u \n",fd);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	FileFDKey fdkey = {};
	int fd;
	int process_fd = 0;

	fd = PT_REGS_PARM1_CORE(regs);


	int *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	if(fdrelevant){
		if(*fdrelevant == fd){
			
			//bpf_printk("This fd is important but we already processed it \n");

			struct fault_key fault_to_inject = {
				pid,
				WRITE_FILE,
			};

			struct fault_description *description_of_fault;

			description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);

			if (description_of_fault){
					if (description_of_fault->on){
						if (writes_blocked < description_of_fault->occurences){
							writes_file_blocked+=1;
							bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
						}
						else if(description_of_fault->occurences == 0){
							bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

						}
						else{
							writes_file_blocked = 0;
							description_of_fault->on = 0;
						}
					}
			}
		}
		if(*fdrelevant == 0){
			//bpf_printk("fdrelevant is 0 \n");
			process_fd = 1;
		}
		else{
			//bpf_printk("Already saw the fd and this one is not important %d \n",fd);
			//It means w already found the relevant fd thus this one is not relevant.
		}
	}else{
		//process_fd = 1;
	}

	if (fd > 0 && process_fd){
        //bpf_printk("%d and pid is %d \n",fd,pid);

        struct file *file = get_file_from_fd(fd);

        if(!file){
            //bpf_printk("File not found \n");
            return 1;
        }

        struct path path = get_path_from_file(file);

        struct inode *inode = get_inode_from_path(&path);

        if (!inode) return 2;
        if (get_file_tag(&fdkey, inode)) return 2;

        EventPath event_path = {};
        event_path.etype = 0;
        event_path.n_ref = 0;
        event_path.index = 0;
        event_path.cpu = bpf_get_smp_processor_id();

        FileInfo fi = {};

        bpf_probe_read(&fi.file_type, sizeof(fi.file_type), &inode->i_mode);

        if (get_file_path(&path, &event_path, &fi) != 0) return 2;

        struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&pid);

        if(file_open){
            if(equal_to_true(file_open,&(fi.filename[fi.offset]),fi.offset)){
				//bpf_printk("%s and %s and pid is %lu and fd is %d \n",&file_open->filename,&(fi.filename[fi.offset]),pid,fd);
				bpf_map_update_elem(&relevant_fd,&pid,&fd,BPF_ANY);

				struct fault_key fault_to_inject = {
					pid,
					WRITE_FILE,
				};

				struct fault_description *description_of_fault;

				description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);


				if (description_of_fault){
					if (description_of_fault->on){
						if (writes_blocked < description_of_fault->occurences){
							writes_file_blocked+=1;
							bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
						}
						else if(description_of_fault->occurences == 0){
							bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

						}
						else{
							writes_file_blocked = 0;
							description_of_fault->on = 0;
						}
					}
				}
                
            }
        }

    }


	struct fault_key fault_to_inject = {
		pid,
		WRITE,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);


	if (description_of_fault){
		if (description_of_fault->on){
			if (writes_blocked < description_of_fault->occurences){
				writes_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else if(description_of_fault->occurences == 0){
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

			}
			else{
				writes_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(WRITES,WRITE_HOOK,pid);
	

	return 0;
}

SEC("kretprobe/__x64_sys_write")
int BPF_KRETPROBE(__x64_sys_ret_write,struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	struct fault_key fault_to_inject = {
		pid,
		WRITE_RET,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);

	if (description_of_fault){
		if (description_of_fault->on){
			if (writes_ret_overrun < description_of_fault->occurences){
				writes_ret_overrun+=1;
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else if(description_of_fault->occurences == 0){
				bpf_printk("Write ret override \n");
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else{
				writes_ret_overrun = 0;
				description_of_fault->on = 0;
			}
		}
	}

	return 0;

}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(__x64_sys_read,struct pt_regs *regs)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	struct fault_key fault_to_inject = {
		pid,
		READ,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);

	if (description_of_fault){
		if (description_of_fault->on){
			if (reads_blocked < description_of_fault->occurences){
				reads_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else if(description_of_fault->occurences == 0){
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

			}
			else{
				reads_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(READS,READ_HOOK,pid);

	return 0;
}


SEC("kprobe/__x64_sys_close")
int BPF_KPROBE(__x64_sys_close,struct pt_regs *regs)
{
	//safe so if other ebpf runs it does not change this value

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	int fd = PT_REGS_PARM1_CORE(regs);

	int *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	if(fdrelevant){
		if(*fdrelevant == fd){
			int zero = 0;
			bpf_map_update_elem(&relevant_fd,&pid,&zero,BPF_ANY);
		}
	}


	return 0;
}

SEC("kprobe/__x64_sys_open")
int BPF_KPROBE(__x64_sys_open,struct pt_regs *regs)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	struct fault_key fault_to_inject = {
		pid,
		OPEN,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);

	if (description_of_fault){
		if (description_of_fault->on){
			if (opens_blocked < description_of_fault->occurences){
				opens_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else if(description_of_fault->occurences == 0){
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

			}
			else{
				opens_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(OPENS,OPEN_HOOK,pid);

	return 0;
}

SEC("kprobe/__x64_sys_mkdir")
int BPF_KPROBE(__x64_sys_mkdir)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	struct fault_key fault_to_inject = {
		pid,
		MKDIR,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);

	if (description_of_fault){
		if (description_of_fault->on){
			if (mkdir_blocked < description_of_fault->occurences){
				mkdir_blocked+=1;
				bpf_printk("Blocked MKDIR \n");
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else if(description_of_fault->occurences == 0){
				bpf_printk("Blocked MKDIR \n");
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);

			}
			else{
				mkdir_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(DIRCREATED,MKDIR_HOOK,pid);

	return 0;
}

SEC("ksyscall/newfstatat")
//SEC("kprobe/__x64_sys_newfstatat")
int BPF_KPROBE(__x64_sys_newfstatat)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	
	struct fault_key fault_to_inject = {
		pid,
		NEWFSTATAT,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);

	if (description_of_fault){
		if (description_of_fault->on){
			if (newfstatat_blocked < description_of_fault->occurences){
				bpf_printk("Blocked STAT with return value %d and tid %d \n",description_of_fault->return_value,tid);
				newfstatat_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
			}
			else if(description_of_fault->occurences == 0){
				bpf_printk("Blocked STAT with return value %d and tid %d \n",description_of_fault->return_value,tid);
				bpf_override_return((struct pt_regs *) ctx, description_of_fault->return_value);
				

			}
			else{
				newfstatat_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(NEWFSTATAT_COUNT,NEWFSTATAT_HOOK,pid);

	return 0;
}