// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobes.h"
#include "bits.bpf.h"
#include "aux.h"
#include "maps.bpf.h"
#include "state_processor.bpf.h"
const volatile pid_t targ_tgid = 0;
const volatile int units = 0;
const volatile bool filter_cg = false;
const volatile char funcname[FUNCNAME_MAX];

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
	__type(key, struct fault_key);
	__type(value, struct fault_description);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faults_specification SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_FAULTS);
	__type(key, int);
	__type(value, struct simplified_fault);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faults SEC(".maps");



struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, char[FUNCNAME_MAX]);
	__type(value,u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} funcnames SEC(".maps");

/* key: pid.  value: start time */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, u32);
	__type(value, u64);
} starts SEC(".maps");

__u32 hist[MAX_SLOTS] = {};
const volatile int fault_count = 0;
const volatile int time_only = 0;

// static inline int process_current_state(int state_key, int pid){

// 	struct info_key information = {
// 		pid,
// 		state_key
// 	};

// 	struct info_state *current_state;

// 	current_state = bpf_map_lookup_elem(&relevant_state_info,&information);
	
// 	if (current_state){

// 		current_state->current_value++;
// 		u64 value = current_state->current_value;
// 		if(current_state->relevant_states){
// 			for (int i=0;i<fault_count;i++){
// 				if (current_state->relevant_states[i]){
// 					u64 relevant_value = current_state->relevant_states[i];
// 					if (relevant_value == value && relevant_value != 0){

// 						struct event *e;

// 						/* reserve sample from BPF ringbuf */
// 						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 						if (!e)
// 							return 0;

// 						e->type = state_key;
// 						e->pid = pid;
// 						e->state_condition = value;
// 						bpf_ringbuf_submit(e, 0);
// 						return 0;
// 					}
// 					if(current_state->repeat && (value % relevant_value == 0)){
// 						struct event *e;

// 						/* reserve sample from BPF ringbuf */
// 						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 						if (!e)
// 							return 0;

// 						e->type = state_key;
// 						e->pid = pid;
// 						e->state_condition = relevant_value;
// 						bpf_ringbuf_submit(e, 0);
// 						return 0;
// 					}
// 					//bpf_printk("Skipped \n");
// 					}
// 					return 0;
// 				}
				
// 		}
// 	}
// }



static void entry(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = id;

	int result = process_current_state(CALLCOUNT,pid,fault_count,time_only,&relevant_state_info,&faults_specification,&faults);

}


SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{	
	entry(ctx);
	return 0;
}

static void exit(void)
{
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
	exit();
	return 0;
}

SEC("fexit/dummy_fexit")
int BPF_PROG(dummy_fexit)
{
	return 0;
}

SEC("fentry/dummy_fentry")
int BPF_PROG(dummy_fentry)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";