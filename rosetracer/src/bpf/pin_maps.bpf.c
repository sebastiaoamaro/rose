// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define HISTORY_SIZE 1048576

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 512);
} uprobes_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct event);
	__uint(max_entries, HISTORY_SIZE);
} history SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pair);
	__type(value, struct network_info);
	__uint(max_entries, 128);
} network_information SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct event);
	__uint(max_entries, HISTORY_SIZE);
} history_delays SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
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
	int ret;
	u32 arg1;
	u32 arg2;
	u32 arg3;
	u32 arg4;
};