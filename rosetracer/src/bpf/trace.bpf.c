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


enum tag { WRITE = 0, READ = 1 };

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
        return 1;
    } else {
        // PID is not in the map
        //bpf_printk("PID %d is not in the map\n", key);
        return 0;
    }
}

SEC("tp/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{	
	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;
	size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

	long unsigned int buff_addr = ctx->args[1];

	const unsigned int local_buff_size = 64;
    char local_buff[local_buff_size] = { 0x00 };

	bpf_probe_read_user(&local_buff, 64, (void*)buff_addr);

	int zero = 0;
	int *pid_trace = bpf_map_lookup_elem(&pids,&zero);

	if(!pid_trace)
		return 0;
	//bpf_printk("tracepoint write %s \n",local_buff);

	struct io_op io_op = {
	};	

	io_op.tag = WRITE;

	io_op.pid = pid;

	bpf_probe_read(&(io_op.buffer),64,local_buff);

	bpf_map_update_elem(&io_ops, &io_ops_counter, &io_op, BPF_ANY);

	io_ops_counter++;


	return 0;

}

SEC("tp/raw_syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{	

	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

	size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;


	 // Get FD
    unsigned int fd = (unsigned int)ctx->args[0];

	// Store buffer address from arguments in map
    long unsigned int buff_addr = ctx->args[1];

	//Might be usefull later, but since exit does not have fd it is not relevant
	struct operation_info op_info = {
		pid,
		buff_addr
	};

    bpf_map_update_elem(&map_buff_addrs, &pid, &op_info, BPF_ANY);
	//bpf_printk("tracepoint read \n");
	return 0;

}

SEC("tp/raw_syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{

	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

	size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

	long unsigned int pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid);
    if (pbuff_addr == 0) {
        return 0;
    }

	long int buff_size = ctx->ret;


	long unsigned int buff_addr = pbuff_addr;
	const unsigned int local_buff_size = 64;
    char local_buff[local_buff_size] = { 0x00 };

	//read only 64 bytes
	long int read_size = 64;

	bpf_probe_read(&local_buff, read_size, (void*)buff_addr);

	//bpf_printk("tracepoint read %s\n",local_buff);

	struct io_op io_op = {};	

	io_op.tag = READ;

	io_op.pid = pid;

	bpf_probe_read(&(io_op.buffer),64,local_buff);

	bpf_map_update_elem(&io_ops, &io_ops_counter, &io_op, BPF_ANY);

	struct io_op *io_op_test = bpf_map_lookup_elem(&io_ops, &io_ops_counter);

	if(io_op_test){
		//bpf_printk("This is %d a Have: %s counter is %d",io_op_test->tag,io_op_test->buffer,io_ops_counter);
	}

	io_ops_counter++;

	

	return 0;

}

SEC("tp/syscalls/sys_enter")
int trace_sys_enter(raw_syscalls, sys_enter) {

	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

	//Need to save
    u64 time = bpf_ktime_get_ns();

	bpf_map_update_elem(&syscalls_time, &pid_tgid, &time, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {

	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

	u64 *time_start = bpf_map_lookup_elem(&syscalls_time, &pid_tgid);

	if(!time_start)
		return 0;

	u64 time_end = bpf_ktime_get_ns();

	u64 time = time_end - *time_start;

	int ret = ctx->ret;

	int id = ctx->id;

	struct syscall_op syscall_op = {
		id,
		pid_tgid,
		ret,
		time
	};

	bpf_map_update_elem(&syscalls, &syscall_counter, &syscall_op, BPF_ANY);

	syscall_counter++;

    return 0;
}
