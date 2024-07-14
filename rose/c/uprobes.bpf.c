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


/* key: pid.  value: start time */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, u32);
	__type(value, u64);
} starts SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} leader SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nodes SEC(".maps");



__u32 hist[MAX_SLOTS] = {};
const volatile int fault_count = 0;
const volatile int time_only = 0;
const volatile int cond_pos = 0;

const volatile int primary_function = 0;


static void entry(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	//bpf_printk("in uprobe for pid %d and tgid %d\n",pid,tid);
	int result = process_current_state(cond_pos,pid,fault_count,time_only,&relevant_state_info,&faults_specification,&faults,&rb,&leader,&nodes);

}

static void switch_leader(struct pt_regs *ctx)
{	
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	int pos = 0;

	int *leader_pointer = bpf_map_lookup_elem(&nodes,&pos);
	
	int *leader_pid = 0;

	if(leader_pointer)
		leader_pid = *leader_pointer;

	
	bpf_map_update_elem(&leader,&pos,&pid,BPF_ANY);

	bpf_printk("Leader switched to %d \n",pid);

	//Update nodes in node map

	bpf_map_update_elem(&nodes,&leader_pid,&pos,BPF_ANY);

	bpf_map_update_elem(&nodes,&pid,&pos,BPF_ANY);

	bpf_printk("Updated nodes %d \n",pid);

	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e){
		bpf_printk("Failed to reserve \n");
		return;
	}
	e->type = LEADER_CHANGE;
	e->pid = pid;
	bpf_ringbuf_submit(e, 0);
}


SEC("kprobe/dummy_kprobe")
int BPF_KPROBE(dummy_kprobe)
{	
	if (primary_function){
		switch_leader(ctx);
	}else{
		entry(ctx);
	}
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