// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
//#include <stddef.h>
//#include <linux/bpf.h>
//#include <linux/if_ether.h>
//#include <linux/ip.h>
//#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "aux.h"
#include "tc.h"
#include "maps.bpf.h"


#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF

#define TC_ACT_OK	0
#define TC_ACT_SHOT 2
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_HLEN	14

char __license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct info_key);
	__type(value, struct info_state);
	 __uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_state_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct fault_key);
	__type(value, struct fault_description);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faults_specification SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct tc_key);
	__type(value, __be32[MAX_IPS_BLOCKED]);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");


const volatile __u32 if_index = 0;
const volatile int fault_count = 0;
const volatile int network_direction = 0;
static int packets_dropped = 0;

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("tc")
int monitor(struct __sk_buff *ctx)
{
	struct fault_key fault_to_inject_networkiso = {
		0,
		NETWORK_ISOLATION,
	};


	struct fault_description *description_of_fault_netiso;

	description_of_fault_netiso = bpf_map_lookup_elem(&faults_specification,&fault_to_inject_networkiso);


	if (description_of_fault_netiso){
		if (description_of_fault_netiso->on){
			//bpf_printk("Blocking packet in %d \n ",network_direction);
			return TC_ACT_SHOT;
		}
	}

	struct fault_key fault_to_inject_droppacket = {
		0,
		DROP_PACKETS,
	};

	struct fault_description *description_of_fault_drop;

	description_of_fault_drop = bpf_map_lookup_elem(&faults_specification,&fault_to_inject_droppacket);
	

	if (description_of_fault_drop){
		if (description_of_fault_drop->on){
			if (packets_dropped <= description_of_fault_drop->occurences){
				packets_dropped++;
				//bpf_printk("Blocked packet \n");
				return TC_ACT_SHOT;
			}
			else{
				packets_dropped = 0;
				description_of_fault_drop->on = 0;
			}
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


	struct fault_key fault_to_inject_blockips = {
		0,
		BLOCK_IPS,
	};

	__be32* ips;

	//check if we are at the state to block ips
	struct fault_description *description_of_fault_block;

	description_of_fault_block = bpf_map_lookup_elem(&faults_specification,&fault_to_inject_blockips);

	if (description_of_fault_block){
		//bpf_printk("Time to block_ips in direction %d \n",network_direction);

		struct tc_key key = {
				if_index,
				network_direction
			};


		if (description_of_fault_block->on){
			ips = bpf_map_lookup_elem(&blocked_ips,&key);
			if(ips){
				for(int i=0;i<MAX_IPS_BLOCKED;i++){
					if (ips[i]){
						//if (network_direction == 2){
						if(network_direction == 1){
							if(ips[i] == pair.src_addr){
								//bpf_printk("e->src_addr is %d and e->dst_addr is %d ip is %d and network dir is %d \n",pair.src_addr,pair.dst_addr,ips[i],network_direction);
								//bpf_printk("Blocked packet by src \n");
								return TC_ACT_SHOT;
							}
						}
						//if (network_direction == 1){
						if(network_direction == 2){
							if(ips[i] == pair.dst_addr){
								//bpf_printk("e->src_addr is %d and e->dst_addr is %d ip is %d and network dir is %d \n",pair.src_addr,pair.dst_addr,ips[i],network_direction);
								//bpf_printk("Blocked packet by dest\n");
								return TC_ACT_SHOT;
							}
						}
					}
				}

		}else{
			//bpf_printk("Ips is NULL and if_index is %d \n",if_index);
			return 0;
			}
		}
	}


	return TC_ACT_OK;
}
