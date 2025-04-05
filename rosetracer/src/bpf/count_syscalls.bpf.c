// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))

// Map to fold the buffer sized from 'read' calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, int);
    __type(value, struct operation_info);
} map_buff_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 64);
} pids SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct io_op);
	__uint(max_entries, 32768);
} io_ops SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct syscall_op);
	__uint(max_entries, 32768);
} syscalls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 8192);
} syscalls_time SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 8192);
} syscalls_counter SEC(".maps");



struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 8192);
} syscalls_counter_array SEC(".maps");

struct accept_args_t
{
    struct sockaddr_in *addr;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct accept_args_t);
} active_accept_args_map SEC(".maps");

// Define a BPF map to store identifiers for each uprobe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4098);
    __type(key, u64);
    __type(value, u32);
} uprobe_map SEC(".maps");


enum tag { WRITE = 1, READ = 2 };

struct event {
	u8 tag;
	u64 pid;
};

struct syscall_op {
	int id;
	u64 pid_tgid;
	int ret;
	u64 time;
};

struct io_op {
	int tag;
	int pid;
	int size;
	char buffer[64];
};

struct operation_info{
	int pid;
	long unsigned int buff_addr;
};

volatile int io_ops_counter = 0;
volatile int syscall_counter = 0;
const volatile int pid_counter = 0;


/* trigger creation of event struct in skeleton code */
struct event _event = {};


static inline int check_pid_prog() {
    u32 key = bpf_get_current_pid_tgid() >> 32; // Get current PID
    u32 *value;

    value = bpf_map_lookup_elem(&pids, &key);
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


SEC("tp/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {

	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

	int id = ctx->id;

	int *counter = bpf_map_lookup_elem(&syscalls_counter_array,&id);

	if (counter){
		int new_counter = *counter + 1;
		bpf_map_update_elem(&syscalls_counter_array,&id,&new_counter,BPF_ANY);
		//bpf_printk("Inserted %d for %d",id,new_counter);
	}else{
		int zero = 0;
		bpf_map_update_elem(&syscalls_counter_array,&id,&zero,BPF_ANY);
	}

    return 0;
}

SEC("tp/syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

    return 0;
}
