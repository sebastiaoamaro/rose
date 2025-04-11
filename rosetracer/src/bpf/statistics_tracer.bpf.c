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
        //bpf_printk("PID %d is in the map\n", key);
        return key;
    } else {
        // PID is not in the map
        //bpf_printk("PID %d is not in the map\n", key);
        return 0;
    }
}


static inline int update_event_counter(){
	if (event_counter == HISTORY_SIZE - 1) {
		event_counter = 0;
	}
	else
		event_counter++;
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

		bpf_printk("Pid %d &Found func %d\n", pid, cookie);
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
			1
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
