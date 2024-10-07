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


// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, struct uprobe_key);
// 	__type(value, int);
// 	__uint(max_entries, 8192);
// } uprobe_counters SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, struct uprobe_key);
// 	__type(value, int);
// 	__uint(max_entries, 8192);
// } uprobe_ret_counters SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 512);
} uprobes_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct uprobe_key);
	__uint(max_entries, 32768);
} called_functions SEC(".maps");


volatile int uprobe_counter = 0;
volatile int uprobe_counter_ret = 0;

struct accept_args_t
{
    struct sockaddr_in *addr;
};

struct uprobe_key{
	int pid;
	int tid;
	int cookie;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct accept_args_t);
} active_accept_args_map SEC(".maps");


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
volatile int called_functions_counter = 0;

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

static inline int check_iops_counters(){
	if (io_ops_counter == 32767)
		io_ops_counter = 0;
	return 0;
}

static inline int check_syscall_counters(){
	if (syscall_counter == 32767)
		syscall_counter = 0;
	return 0;
}

static inline int check_called_functions_counters(){
	if (called_functions_counter == 32767)
		called_functions_counter = 0;
	return 0;
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
	
	//bpf_printk("tracepoint write %s \n",local_buff);


	struct io_op io_op = {
	};	

	io_op.tag = WRITE;

	io_op.pid = pid;

	bpf_probe_read(&(io_op.buffer),64,local_buff);

	bpf_map_update_elem(&io_ops, &io_ops_counter, &io_op, BPF_ANY);

	io_ops_counter++;

	check_iops_counters();


	return 0;

}

SEC("tp/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{	

	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

	size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;


	 // Get FD
    //unsigned int fd = (unsigned int)ctx->args[0];

	// Store buffer address from arguments in map
    long unsigned int buff_addr = ctx->args[1];

	struct operation_info op_info = {
		pid,
		buff_addr
	};

    bpf_map_update_elem(&map_buff_addrs, &pid, &op_info, BPF_ANY);
	//bpf_printk("tracepoint read \n");
	return 0;

}

SEC("tp/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{

	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

	size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

	struct operation_info *op_info = bpf_map_lookup_elem(&map_buff_addrs, &pid);

	if (!op_info)
		return 0;

	long unsigned int pbuff_addr = op_info->buff_addr;

    if (pbuff_addr == 0) {
        return 0;
    }

	long int buff_size = ctx->ret;


	long unsigned int buff_addr = pbuff_addr;
	const unsigned int local_buff_size = 16;
    char local_buff[local_buff_size] = { 0x00 };

	//read only 64 bytes
	long int read_size = 16;

	bpf_probe_read(&local_buff, read_size, (void*)buff_addr);

	struct io_op io_op = {};	

	io_op.tag = READ;

	io_op.pid = pid;

	io_op.size = buff_size;

	bpf_probe_read(&(io_op.buffer),64,local_buff);

	bpf_map_update_elem(&io_ops, &io_ops_counter, &io_op, BPF_ANY);

	struct io_op *io_op_test = bpf_map_lookup_elem(&io_ops, &io_ops_counter);

	if(io_op_test){
		//bpf_printk("This is %d Have: %s counter is %d",io_op_test->tag,io_op_test->buffer,io_ops_counter);
	}

	io_ops_counter++;
	check_iops_counters();

	

	return 0;

}

SEC("tp/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {

	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

	int id = ctx->id;

	//Need to save
    //u64 time = bpf_ktime_get_ns();

	//bpf_map_update_elem(&syscalls_time, &pid_tgid, &time, BPF_ANY);

	// int *counter = bpf_map_lookup_elem(&syscalls_counter,&id);

	// if (counter){
	// 	int new_counter = *counter + 1;
	// 	bpf_map_update_elem(&syscalls_counter,&id,&new_counter,BPF_ANY);
	// 	//bpf_printk("Inserted %d for %d",id,new_counter);
	// }else{
	// 	int zero = 0;
	// 	bpf_map_update_elem(&syscalls_counter,&id,&zero,BPF_ANY);
	// }


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

	int ret = ctx->ret;

	if (ret<0){

		u64 pid_tgid = bpf_get_current_pid_tgid();

		//u64 *time_start = bpf_map_lookup_elem(&syscalls_time, &pid_tgid);

		//if(!time_start)
			//return 0;

		u64 time_end = bpf_ktime_get_ns();

		//u64 time = time_end - *time_start;

		int id = ctx->id;
		struct syscall_op syscall_op = {
			id,
			pid_tgid,
			ret,
			time_end
		};

		bpf_map_update_elem(&syscalls, &syscall_counter, &syscall_op, BPF_ANY);

		syscall_counter++;
		check_syscall_counters();
	}

    return 0;
}


// SEC("tracepoint/syscalls/sys_enter_accept")
// int trace_accept_enter(struct trace_event_raw_sys_enter *ctx)
// {
//     u64 id = bpf_get_current_pid_tgid();

//     struct accept_args_t accept_args = {};
//     accept_args.addr = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
//     bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);
//     //bpf_printk("enter_accept accept_args.addr: %llx\n", accept_args.addr);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_exit_accept")
// int trace_accept_exit(struct trace_event_raw_sys_exit *ctx)
// {

//     u64 id = bpf_get_current_pid_tgid();

//     struct accept_args_t *args =
//         bpf_map_lookup_elem(&active_accept_args_map, &id);
//     if (args == NULL)
//     {
//         return 0;
//     }
//     //bpf_printk("exit_accept accept_args.addr: %llx\n", args->addr);
//     int ret_fd = (int)BPF_CORE_READ(ctx, ret);
//     if (ret_fd <= 0)
//     {
//         return 0;
//     }

//     bpf_map_delete_elem(&active_accept_args_map, &id);
// }

// SEC("tracepoint/syscalls/sys_enter_connect")
// int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
// {
// 	u64 id = bpf_get_current_pid_tgid();

//     struct accept_args_t accept_args = {};
//     accept_args.addr = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);
// }

// SEC("tracepoint/syscalls/sys_exit_connect")
// int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
// {
// 	u64 id = bpf_get_current_pid_tgid();

// }

// SEC("uprobe")
// int handle_uprobe(struct pt_regs *ctx) {
	
// 	uprobe_counter++;
// 	u64 cookie = bpf_get_attach_cookie(ctx);

// 	u32 pid = bpf_get_current_pid_tgid() >> 32; // Get current PID

// 	struct uprobe_key key = {
// 		pid,
// 		cookie
// 	};

// 	int *counter = bpf_map_lookup_elem(&uprobe_counters,&key);

// 	if (counter){
// 		int new_counter = *counter + 1;
// 		bpf_map_update_elem(&uprobe_counters,&key,&new_counter,BPF_ANY);
// 		//bpf_printk("Inserted %d for %d",new_counter,cookie);
// 	}else{
// 		int zero = 0;
// 		bpf_map_update_elem(&uprobe_counters,&key,&zero,BPF_ANY);
// 		//bpf_printk("NORMAL:Inserted 0 in cookie %d for pid %d \n",cookie,pid);
// 	}

// 	bpf_printk("IN UPROBE with count %d \n",uprobe_counter);
//     return 0;
// }

// SEC("uprobe")
// int handle_uprobe_ret(struct pt_regs *ctx) {
	
// 	uprobe_counter_ret++;
// 	u64 cookie = bpf_get_attach_cookie(ctx);

// 	u32 pid = bpf_get_current_pid_tgid() >> 32; // Get current PID

// 	struct uprobe_key key = {
// 		pid,
// 		cookie
// 	};

// 	int *counter = bpf_map_lookup_elem(&uprobe_ret_counters,&key);

// 	if (counter){
// 		int new_counter = *counter + 1;
// 		bpf_map_update_elem(&uprobe_ret_counters,&key,&new_counter,BPF_ANY);
// 		//bpf_printk("Inserted %d for %d",new_counter,cookie);
// 	}else{
// 		int zero = 0;
// 		bpf_map_update_elem(&uprobe_ret_counters,&key,&zero,BPF_ANY);
// 		//bpf_printk("RET:Inserted 0 in cookie %d for pid %d \n",cookie,pid);
// 	}

// 	bpf_printk("IN UPROBE_ret with count %d \n",uprobe_counter_ret);
//     return 0;
// }

SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx) {
	

		u64 cookie = bpf_get_attach_cookie(ctx);

		u64 pid_tgid = bpf_get_current_pid_tgid();
			u32 pid = pid_tgid >> 32; // Extract the PID (upper 32 bits)
			u32 tid = (u32)pid_tgid;  // Extract the TID (lower 32 bits)


		int *counter = bpf_map_lookup_elem(&uprobes_counters,&cookie);

		if (counter){
			int new_counter = *counter + 1;
			bpf_map_update_elem(&uprobes_counters,&cookie,&new_counter,BPF_ANY);
			//bpf_printk("Incremented for cookie %d \n",cookie);
		}else{
			int zero = 0;
			bpf_map_update_elem(&uprobes_counters,&cookie,&zero,BPF_ANY);
		}

		struct uprobe_key key = {
			pid,
			tid,
			cookie
		};

		bpf_map_update_elem(&called_functions, &called_functions_counter, &key, BPF_ANY);

		called_functions_counter++;
		check_called_functions_counters();

    return 0;
}