// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define HISTORY_SIZE 1048576

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 64);
} pids SEC(".maps");

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


struct accept_args_t
{
    struct sockaddr_in *addr;
};

struct event {
	u64 type;
	u64 timestamp;
	u64 id;
	u32 pid;
	u32 tid;
	int ret;
	u32 arg1;
	u32 arg2;
	u32 arg3;
	u32 arg4;
};

struct connect_data_t {
    int family;
    __u32 saddr;
};


enum type { SYSCALL_ENTER = 1,SYSCALL_EXIT = 2, UPROBE = 3};

const volatile int pid_counter = 0;
volatile int event_counter = 0;
volatile int delay_counter = 0;

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


static inline int update_event_counter(){
	if (event_counter == HISTORY_SIZE - 1) {
		event_counter = 0;
		bpf_printk("Reset event counter");
	}
	else
		event_counter++;
	return 0;
}

// SEC("tracepoint/syscalls/sys_enter_connect")
// int trace_connect_entry(struct trace_event_raw_sys_enter *ctx) {

// 		int pid_relevant = check_pid_prog();

// 		if (!pid_relevant)
// 			return 0;

//     struct connect_data_t data = {};
//     struct sockaddr_in *addr_in;
    
//     // Get address struct and length from syscall arguments
//     struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[1];
//     int addrlen = (int)ctx->args[2];
    
//     // Check family and extract address information
//     bpf_probe_read_user(&data.family, sizeof(data.family), &uservaddr->sa_family);
    
// 		addr_in = (struct sockaddr_in *)uservaddr;
// 		bpf_probe_read_user(&data.saddr, sizeof(data.saddr), &addr_in->sin_addr.s_addr);

// 		//bpf_printk("Syscall connect called with address %d\n", data.saddr);

// 		bpf_map_update_elem(&connect_map,&pid_relevant, &data.saddr, BPF_ANY);

//     return 0;
// }

SEC("tp/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {

	
		int id = ctx->id;
		if (id == 0 || id == 1 || id == 82 || id == 232 || id == 233 || id == 281 || id == 202 || id ==237 || id == 39 || id == 8 || id == 74){
			return 0;
		}


		int pid_relevant = check_pid_prog();

		if (!pid_relevant)
			return 0;

		u64 pid_tgid = bpf_get_current_pid_tgid();
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

    return 0;
}

SEC("tp/syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {

	
	int id = ctx->id;

	if (id == 233 || id == 202 || id == 39 || id == 257 || id == 82){
		return 0;
	}
	
	int pid_relevant = check_pid_prog();

	if (!pid_relevant)
		return 0;

	int ret = ctx->ret;

	if (ret<0){

		u64 pid_tgid = bpf_get_current_pid_tgid();
		u32 pid = pid_tgid >> 32; // Extract the PID (upper 32 bits)
		u32 tid = (u32)pid_tgid;  // Extract the TID (lower 32 bits)

		u64 timestamp = bpf_ktime_get_ns();
		struct event key = {
			SYSCALL_EXIT,
			timestamp,
			id,
			pid,
			tid,
			ret,
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


SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx) {
		
		int pid_relevant = check_pid_prog();

		if (!pid_relevant)
			return 0;

		u64 cookie = bpf_get_attach_cookie(ctx);

		u64 pid_tgid = bpf_get_current_pid_tgid();
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
		
		if (cookie == 257){
			bpf_printk("cookie with id %d", cookie);
		}

		struct event key = {
			UPROBE,
			timestamp,
			cookie,
			pid,
			tid,
			1,
			0,
			0,
			0,
			0
		};

		bpf_map_update_elem(&history, &event_counter, &key, BPF_ANY);

		update_event_counter();

    return 0;
}

// SEC("xdp")
// int xdp_pass(struct xdp_md *ctx)
// {
//     // Pointers to packet data
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;

//     // Parse Ethernet header
//     struct ethhdr *eth = data;

//     // Check if the packet is a TCP packet
//     if (!is_tcp(eth, data_end)) {
//         return XDP_PASS;
//     }

//     // Cast to IP header
//     struct iphdr *ip = (struct iphdr *)(eth + 1);

//     // Calculate IP header length
//     int ip_hdr_len = ip->ihl * 4;
//     if (ip_hdr_len < sizeof(struct iphdr)) {
//         return XDP_PASS;
//     }

// 		u32 src_ip = ip->saddr;
// 		u32 dst_ip = ip->daddr;

// 		struct pair pair = {
// 			src_ip,
// 			dst_ip
// 		};

// 		struct network_info *net_info = bpf_map_lookup_elem(&network_delays,&pair);
// 		u64 timestamp = bpf_ktime_get_ns();
// 		if (net_info){
// 			u64 delay = timestamp - net_info->last_time_seen;
// 			net_info->last_time_seen = timestamp;
// 			net_info->frequency++;
// 			bpf_map_update_elem(&network_delays,&pair,net_info,BPF_ANY);
// 			if(delay > 5000000000){
// 					struct event event = {
// 						NETWORK_DELAY,
// 						timestamp,
// 						0,
// 						NETWORK_DELAY,
// 						0,
// 						0,
// 						src_ip,
// 						dst_ip,
// 						(delay/1000000),
// 						net_info->frequency
// 					};
// 					//bpf_printk("Found a delay of %llu",delay);
// 					bpf_map_update_elem(&history,&event_counter,&event,BPF_ANY);
		
// 					update_event_counter();
// 			}	
// 		}else{
// 			struct network_info net_info = {
// 				1,
// 				timestamp
// 			};
// 			//bpf_printk("No delay found");
// 			bpf_map_update_elem(&network_delays,&pair,&net_info,BPF_ANY);
// 		}

// 		//bpf_printk("Src ip: %pI4, Dst ip: %pI4",&src_ip,&dst_ip);

//     return XDP_PASS;
// }

