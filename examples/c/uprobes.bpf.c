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

static inline int process_current_state(int state_key, int type, int pid){

	struct info_key information = {
		pid,
		state_key
	};

	struct info_state *current_state;

	current_state = bpf_map_lookup_elem(&relevant_state_info,&information);
	
	if (current_state){

		current_state->current_value++;
		u64 value = current_state->current_value;
		if(current_state->relevant_states){
			for (int i=0;i<fault_count;i++){
				if (current_state->relevant_states[i]){
					u64 relevant_value = current_state->relevant_states[i];
					if (relevant_value == value && relevant_value != 0){

						struct event *e;

						/* reserve sample from BPF ringbuf */
						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
						if (!e)
							return 0;

						e->type = type;
						e->pid = pid;
						e->state_condition = value;
						bpf_ringbuf_submit(e, 0);
						return 0;
					}
					if(current_state->repeat && (value % relevant_value == 0)){
						struct event *e;

						/* reserve sample from BPF ringbuf */
						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
						if (!e)
							return 0;

						e->type = type;
						e->pid = pid;
						e->state_condition = relevant_value;
						bpf_ringbuf_submit(e, 0);
						return 0;
					}
					//bpf_printk("Skipped \n");
					}
					return 0;
				}
				
		}
	}
}

static void entry(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = id;
	u64 nsec;

	// char* argument,argument2;

	// argument = PT_REGS_PARM1(ctx);

	// if(argument)
	// 	bpf_printk("Argument is %s \n",argument);

	// argument2 = PT_REGS_PARM2(ctx);

	// if(argument)
	// 	bpf_printk("Argument2 is %s \n",argument2);


	// int one = 1;

	// int *count = bpf_map_lookup_or_try_init(&funcnames,&funcname,&one);

	// int new_value = 0;
	// if (!count)
	// 	return;
	// if (*count == 0){
	// 	bpf_map_update_elem(&funcnames,&funcname,&one,BPF_ANY);
		
	// }else{
	// 	new_value = *count + 1;
	// 	bpf_map_update_elem(&funcnames,&funcname,&new_value,BPF_ANY);
	// }

	int result = process_current_state(FUNCTIONS,CALLCOUNT,pid);

}

SEC("fentry/dummy_fentry")
int BPF_PROG(dummy_fentry)
{
	entry(ctx);
	return 0;
}

SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{	
	entry(ctx);
	return 0;
}

static void exit(void)
{
	u64 *start;
	u64 nsec = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	u64 slot, delta;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return;

	start = bpf_map_lookup_elem(&starts, &pid);
	if (!start)
		return;

	delta = nsec - *start;

	switch (units) {
	case USEC:
		delta /= 1000;
		break;
	case MSEC:
		delta /= 1000000;
		break;
	}

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist[slot], 1);
}

SEC("fexit/dummy_fexit")
int BPF_PROG(dummy_fexit)
{
	exit();
	return 0;
}

SEC("kretprobe/dummy_kretprobe")
int BPF_KRETPROBE(dummy_kretprobe)
{
	exit();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";