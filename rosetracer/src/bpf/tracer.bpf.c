// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include "aux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define HISTORY_SIZE 1048576
#define MAP_FAILED	((void *) -1)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_tree SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, u32);
	__uint(max_entries, 1024);
} connect_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 512);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} uprobes_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct event);
	__uint(max_entries, HISTORY_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} history SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, int);
	__uint(max_entries, 512);
} pid_tgid_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct process_fd);
	__type(value, char[FILENAME_MAX_SIZE]);
	__uint(max_entries, 1048576);
} fd_to_name SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, char[FILENAME_MAX_SIZE]);
	__uint(max_entries, 512);
} pid_to_open_name SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct process_fd);
	__type(value, int);
	__uint(max_entries, 4096);
} dup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct process_and_syscall);
//	__type(value, long unsigned int);
    __type(value, char[FILENAME_MAX_SIZE]);
	__uint(max_entries, HISTORY_SIZE);
}important_arguments SEC(".maps");


enum type { SYSCALL_ENTER = 1,SYSCALL_EXIT = 2, UPROBE = 3, OPEN = 5};

const volatile int pid_counter = 0;
volatile int event_counter = 0;
volatile int delay_counter = 0;

/* trigger creation of event struct in skeleton code */
struct event _event = {};


static inline int check_pid_prog(u64 pid_tgid) {
    u32 key = pid_tgid >> 32; // Get current PID
    u32 *value;

    value = bpf_map_lookup_elem(&pid_tree, &key);
    if (value) {
        // PID is in the map
        return key;
    } else {
        // PID is not in the map
        return 0;
    }
}


static inline int update_event_counter(){
	if (event_counter == HISTORY_SIZE - 1) {
		event_counter = 0;
		bpf_printk("Reset counter");
	}
	else
		event_counter++;
	return 0;
}

SEC("tp/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {


	long id = ctx->id;
	u64 pid_tgid = bpf_get_current_pid_tgid();

	if (id == 0 || id == 1 || id == 3 || id == 32 || id == 33 || id == 292){

		int pid_relevant = check_pid_prog(pid_tgid);

		if (!pid_relevant)
			return 0;

		int fd = (int)ctx->args[0];

		bpf_map_update_elem(&pid_tgid_fd, &pid_tgid, &fd, BPF_ANY);

		u32 pid = pid_tgid >> 32; // Extract the PID (upper 32 bits)
		u32 tid = (u32)pid_tgid;  // Extract the TID (lower 32 bits)

		u64 timestamp = bpf_ktime_get_ns();

		struct event key = {
			SYSCALL_ENTER,
			timestamp,
			id,
			pid,
			tid,
			fd,
			0,
			0,
			0,
			0
		};

		bpf_map_update_elem(&history, &event_counter, &key, BPF_ANY);
		update_event_counter();

	}
	else if(id == 2 || id == 85){
			int pid_relevant = check_pid_prog(pid_tgid);

			if (!pid_relevant)
				return 0;

			const char *filename = (const char *)ctx->args[0];
			char path[FILENAME_MAX_SIZE + 1] = {};
			int len = bpf_probe_read_user_str(path, sizeof(path), filename);

			bpf_map_update_elem(&pid_to_open_name,&pid_relevant, path, BPF_ANY);
	}

	else if(id == 257){
			int pid_relevant = check_pid_prog(pid_tgid);

			if (!pid_relevant)
				return 0;

			const char *filename = (const char *)ctx->args[1];
			char path[FILENAME_MAX_SIZE + 1] = {};
			int len = bpf_probe_read_user_str(path, sizeof(path), filename);

			bpf_map_update_elem(&pid_to_open_name,&pid_relevant, path, BPF_ANY);

	}else{
    	int pid_relevant = check_pid_prog(pid_tgid);

    	if (!pid_relevant)
    		return 0;

    	u32 pid = pid_tgid >> 32; // Extract the PID (upper 32 bits)
    	u32 tid = (u32)pid_tgid;  // Extract the TID (lower 32 bits)

    	u64 timestamp = bpf_ktime_get_ns();

    	struct event key = {
    		SYSCALL_ENTER,
    		timestamp,
    		id,
    		pid,
    		tid,
    		0,
    		0,
    		0,
    		0,
    		0
    	};

    	bpf_map_update_elem(&history, &event_counter, &key, BPF_ANY);
    	update_event_counter();
	}

    return 0;
}

SEC("tp/syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {

	long id = ctx->id;

	if (id < 0){
		return 0;
	}

	u64 pid_tgid = bpf_get_current_pid_tgid();
	int pid_relevant = check_pid_prog(pid_tgid);

	if (!pid_relevant)
		return 0;
	long int ret = ctx->ret;

	//Failing opens has its own special handling since they we need the filename
	if (ret<0 && id !=9 && id != 12){
		u32 pid = pid_tgid >> 32; // Extract the PID (upper 32 bits)
		u32 tid = (u32)pid_tgid;  // Extract the TID (lower 32 bits)

		u64 timestamp = bpf_ktime_get_ns();

		int fd = 0;
		//bpf_printk("Looking at pid_tgid %d ",pid_tgid);
		int *fd_in_map = bpf_map_lookup_elem(&pid_tgid_fd,&pid_tgid);

		if (fd_in_map){
			fd = *fd_in_map;
		}

		if (id == 262){
		    //verbose = 0;
            struct process_and_syscall psys = {
                id,
                pid_tgid,
            };
            //bpf_printk("Looking for filename for pid_tgid %llu \n",pid_tgid);
		    //long unsigned int *file_addr = bpf_map_lookup_elem(&important_arguments,&psys);
		    char *filename = bpf_map_lookup_elem(&important_arguments,&psys);

       	    if (!filename) {
                //bpf_printk("FAILED, PID_TGID:%llu\n",pid_tgid);
                return 0;
            }
            //long unsigned int buff_addr = *file_addr;
            struct event key = {
     			SYSCALL_EXIT,
     			timestamp,
     			id,
     			pid,
     			tid,
     			fd,
     			0,
     			0,
     			0,
     			ret,
      		};

     	 	//int len = bpf_probe_read_user_str(&key.extra, FILENAME_MAX_SIZE,(void *) buff_addr);
            int len = bpf_probe_read_str(&key.extra, FILENAME_MAX_SIZE,filename);
            if (len <= 0){
                bpf_printk("Failed to read file name with error %d\n", len);
                return 0;
            }

            //bpf_printk("NAME:%s, SIZE:%d, POINTER:%p, PID_TGID:%llu \n",key.extra,key.extra,len,buff_addr,pid_tgid);
            bpf_map_update_elem(&history, &event_counter, &key, BPF_ANY);
            update_event_counter();
			return 0;

	    }else{
			struct event key = {
     			SYSCALL_EXIT,
     			timestamp,
     			id,
     			pid,
     			tid,
     			fd,
     			0,
     			0,
     			0,
     			ret
            };
            if (id == 2 || id == 257 || id == 85){
          		char *path_pointer = bpf_map_lookup_elem(&pid_to_open_name,&pid_relevant);
          		if (path_pointer){
         			int len = bpf_probe_read_str(key.extra, FILENAME_MAX_SIZE+1, path_pointer);
                    if (len <= 0){
                        bpf_printk("Failed to read open name with error %d\n", len);
                        return 0;
                    }
                }
			}
            bpf_map_update_elem(&history, &event_counter, &key, BPF_ANY);
            update_event_counter();
            return 0;
		}

    }

	//Checking for small reads 1-2 bytes
	// else if (id == 0 && ret < 3){
	// 		u32 pid = pid_tgid >> 32; // Extract the PID (upper 32 bits)
	// 		u32 tid = (u32)pid_tgid;  // Extract the TID (lower 32 bits)

	// 		u64 timestamp = bpf_ktime_get_ns();

	// 		int fd = 0;
	// 		//bpf_printk("Looking at pid_tgid %d ",pid_tgid);
	// 		int *fd_in_map = bpf_map_lookup_elem(&pid_tgid_fd,&pid_tgid);

	// 		if (fd_in_map){
	// 			fd = *fd_in_map;
	// 		}


	// 		struct event key = {
	// 			SYSCALL_EXIT,
	// 			timestamp,
	// 			id,
	// 			pid,
	// 			tid,
	// 			fd,
	// 			0,
	// 			0,
	// 			0,
	// 			ret
	// 		};
	// 		bpf_map_update_elem(&history, &event_counter, &key, BPF_ANY);

	// 		update_event_counter();
	// }

	else if (id == 9 || id == 12){
		if (ret == MAP_FAILED){
			u32 pid = pid_tgid >> 32; // Extract the PID (upper 32 bits)
			u32 tid = (u32)pid_tgid;  // Extract the TID (lower 32 bits)

			u64 timestamp = bpf_ktime_get_ns();
			struct event key = {
				SYSCALL_EXIT,
				timestamp,
				id,
				pid,
				tid,
				0,
				0,
				0,
				0,
				-1,
			};
				bpf_map_update_elem(&history, &event_counter, &key, BPF_ANY);

				update_event_counter();
		}
	}

	else if (id == 2 || id == 257 || id == 85){

		char path[FILENAME_MAX_SIZE + 1] = {};

		char *path_pointer = bpf_map_lookup_elem(&pid_to_open_name,&pid_relevant);

		if (path_pointer){

			int len = bpf_probe_read_str(path, FILENAME_MAX_SIZE+1, path_pointer);

			if (len>0 && len<FILENAME_MAX_SIZE+1){
				path[len-1] = '\0';
			}
			else{
				return 0;
			}

			u64 timestamp = bpf_ktime_get_ns();
			struct process_fd fd_info = {
				ret,
				pid_relevant,
				timestamp

			};

			//TODO: Should be an event but good enough for testing
			bpf_map_update_elem(&fd_to_name,&fd_info, &path, BPF_ANY);
			//bpf_printk("Added pid %d, fd %d, ts %llu, path %s",pid_relevant,ret,timestamp,path);

		}

	}

	else if (id ==32 || id == 33 || id == 292){

			int fd = 0;
			//bpf_printk("Looking at pid_tgid %d ",pid_tgid);
			int *fd_in_map = bpf_map_lookup_elem(&pid_tgid_fd,&pid_tgid);

			if (fd_in_map){
				fd = *fd_in_map;
			}
			u64 timestamp = bpf_ktime_get_ns();

			struct process_fd fd_info = {
				fd,
				pid_relevant,
				timestamp

			};
			bpf_map_update_elem(&dup_map,&fd_info,&ret, BPF_ANY);
			//bpf_printk("Added pid %d, fd %d, ts %llu, new_fd %d",pid_relevant,fd,timestamp,ret);

	}
    return 0;
}


SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx) {

		u64 pid_tgid = bpf_get_current_pid_tgid();

		int pid_relevant = check_pid_prog(pid_tgid);

		if (!pid_relevant)
			return 0;

		u64 cookie = bpf_get_attach_cookie(ctx);

		u32 pid = pid_tgid >> 32; // Extract the PID (upper 32 bits)
		u32 tid = (u32)pid_tgid;  // Extract the TID (lower 32 bits)


		u64 timestamp = bpf_ktime_get_ns();

		int *counter = bpf_map_lookup_elem(&uprobes_counters,&cookie);

		if (counter){
			int new_counter = *counter + 1;
			bpf_map_update_elem(&uprobes_counters,&cookie,&new_counter,BPF_ANY);
		}else{
			int zero = 0;
			bpf_map_update_elem(&uprobes_counters,&cookie,&zero,BPF_ANY);
		}

		struct event key = {
			UPROBE,
			timestamp,
			cookie,
			pid,
			tid,
			0,
			0,
			0,
			0,
			1,
		};

		bpf_map_update_elem(&history, &event_counter, &key, BPF_ANY);

		update_event_counter();

    return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent;
    int ppid = 0;

    if (task) {
        parent = task->real_parent;
        if (parent) {
            ppid = parent->pid;
        }
    }

   	int *parent_pid_pointer = bpf_map_lookup_elem(&pid_tree,&ppid);

	if (!parent_pid_pointer) {
	   return 0;
	}

    bpf_printk("ADDED PID:%d, PARENT:%d \n",pid,ppid);
    bpf_map_update_elem(&pid_tree, &pid, &ppid, BPF_ANY);
	return 0;
}
