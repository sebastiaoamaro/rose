// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
//#include <vmlinux.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tc.h"
#include "aux.h"
#include "maps.bpf.h"


#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF

#define TC_ACT_OK	0
#define TC_ACT_SHOT 2
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

char __license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64[512]);
	 __uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_state_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} syscalls_to_fail SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct pair);
    __type(value, __u32);
} network SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __be32[MAX_IPS_BLOCKED]);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");


const volatile __u32 if_index = 0;
const volatile int fault_count = 0;

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	int isolation = NETWORK_ISOLATION;

	int* isolate_network = bpf_map_lookup_elem(&syscalls_to_fail,&isolation);

	if (isolate_network){
		if (*isolate_network){
			bpf_printk("Blocked packet\n");
			return TC_ACT_SHOT;
		}
	}


	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	__u32 nhoff = ETH_HLEN;
	__u16 proto;

	__u32 ip_proto = 0;

	struct pair pair = {
		0,
		0
	};
	bpf_skb_load_bytes(ctx, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP)
		return 0;


	if (ip_is_fragment(ctx, nhoff))
		return 0;

	//bpf_printk("Got IP packet: tot_len: %d, ttl: %d, proto: %d \n", bpf_ntohs(l3->tot_len), l3->ttl,ctx->protocol);

	// e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	// if (!e)
	// 	return 0;
	
	bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, protocol), &(ip_proto), 1);

	if (ip_proto != IPPROTO_GRE) {
		bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, saddr), &(pair.src_addr), 4);
		bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, daddr), &(pair.dst_addr), 4);
	}

	//bpf_printk("e->src_addr is %d and e->dst_addr is %d \n",pair.src_addr,pair.dst_addr);

	int block_ips_flag = BLOCK_IPS;

	__be32* ips;

	//check if we are at the state to block ips
	int* block_ips = bpf_map_lookup_elem(&syscalls_to_fail,&block_ips_flag);
	if (block_ips){
		//bpf_printk("Time to block_ips \n");
		if (*block_ips){
			ips = bpf_map_lookup_elem(&blocked_ips,&if_index);
			if(ips){
				//bpf_printk("Have list of ips \n");
				for(int i=0;i<MAX_IPS_BLOCKED;i++){
					if (ips[i]){
						if(ips[i] == pair.src_addr || ips[i] == pair.dst_addr){
							//bpf_printk("Blocked packet \n");
							//bpf_ringbuf_discard(e, 0);
							return TC_ACT_SHOT;
						}
					}
				}

		}else{
			//bpf_printk("Ips is NULL and if_index is %d \n",if_index);
			//bpf_ringbuf_discard(e, 0);
			return 0;
			}
		}
	}

	__u32 *current_bytes;
	__u32 new_bytes;
	__u32 zero = 0;

	current_bytes = bpf_map_lookup_or_try_init(&network,&pair,&zero);

	if (current_bytes){
		new_bytes = ctx->len + *current_bytes;

		bpf_map_update_elem(&network,&pair,&new_bytes,BPF_ANY);
	}


	// e->type = TC;
	// e->ifindex = if_index;

	//TRACING CHANGE LATER
	//bpf_ringbuf_discard(e, 0);

	return TC_ACT_OK;
}
