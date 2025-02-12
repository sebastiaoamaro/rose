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
	__type(key, struct pair);
	__type(value, struct network_info);
	__uint(max_entries, 128);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} network_information SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct event);
	__uint(max_entries, HISTORY_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} history_delays SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} event_counter_for_delays SEC(".maps");

struct pair
{
	u32 src;
	u32 dst;
};

struct network_info
{
	u32 frequency;
	u64 last_time_seen;
};

struct event {
	u64 type;
	u64 timestamp;
	u64 id;
	u32 pid;
	u32 tid;
	u32 arg1;
	u32 arg2;
	u32 arg3;
	u32 arg4;
	int ret;
};


enum type {NETWORK_DELAY = 4 };
volatile int event_counter = 0;

static inline int update_event_counter(){
	int zero = 0;
	int *counter = bpf_map_lookup_elem(&event_counter_for_delays, &zero);
	if (counter){
		bpf_printk("Counter is %D",*counter);
		if (*counter == HISTORY_SIZE - 1) {
			counter = 0;
			bpf_printk("Reset event counter");
		}else{
			(*counter)++;
			event_counter = *counter;
			bpf_map_update_elem(&event_counter_for_delays, &zero, counter, BPF_ANY);
		}
	}
	else{
		//bpf_printk("Started counter");
		int one = 1;
		bpf_map_update_elem(&event_counter_for_delays, &zero, &one, BPF_ANY);
	}

	return 0;
}

static bool is_tcp(struct ethhdr *eth, void *data_end)
{
    // Ensure Ethernet header is within bounds
    if ((void *)(eth + 1) > data_end)
        return false;

    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Ensure IP header is within bounds
    if ((void *)(ip + 1) > data_end)
        return false;

    // Check if the protocol is TCP
    if (ip->protocol != IPPROTO_TCP)
        return false;

    return true;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    // Pointers to packet data
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;

    // Check if the packet is a TCP packet
    if (!is_tcp(eth, data_end)) {
        return XDP_PASS;
    }

    // Cast to IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Calculate IP header length
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

		u32 src_ip = ip->saddr;
		u32 dst_ip = ip->daddr;

		struct pair pair = {
			src_ip,
			dst_ip
		};

		struct network_info *net_info = bpf_map_lookup_elem(&network_information,&pair);
		u64 timestamp = bpf_ktime_get_ns();
		if (net_info){
			u64 delay = timestamp - net_info->last_time_seen;
			net_info->last_time_seen = timestamp;
			net_info->frequency++;
			bpf_map_update_elem(&network_information,&pair,net_info,BPF_ANY);
			if(delay > 5000000000){
					struct event event = {
						NETWORK_DELAY,
						timestamp,
						0,
						NETWORK_DELAY,
						0,
						src_ip,
						dst_ip,
						(delay/1000000),
						net_info->frequency,
						0
					};
					//bpf_printk("Found a delay of %llu from %pI4 to %pI4",delay,&src_ip,&dst_ip);
					bpf_map_update_elem(&history_delays,&event_counter,&event,BPF_ANY);
		
					update_event_counter();
			}	
		}else{
			struct network_info net_info = {
				1,
				timestamp
			};
			//bpf_printk("No delay found");
			bpf_map_update_elem(&network_information,&pair,&net_info,BPF_ANY);
		}

		//bpf_printk("Src ip: %pI4, Dst ip: %pI4",&src_ip,&dst_ip);

    return XDP_PASS;
}