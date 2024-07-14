#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "aux.h"
#include "fs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//Struct to hold faults
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_FAULTS);
	__type(key, int);
	__type(value, struct simplified_fault);
} faults SEC(".maps");


//Struct to hold faults
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} time SEC(".maps");

//ARRAYS ARE NECESSARY AS VALUES BECAUSE DIFFERENT FAULT MIGHT HAVE THE SAME STATE PROPERTY
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct info_key);
	__type(value, struct info_state);
} relevant_state_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key,struct fault_key);
	__type(value, struct fault_description);
} faults_specification SEC(".maps");

//Key is network device index, value is array of IPS to block incoming (for now)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct tc_key);
	__type(value, __be32[MAX_IPS_BLOCKED]);
} blocked_ips SEC(".maps");

//Key is pid + fd
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct info_key);
	__type(value,struct file_info_simple);
} files SEC(".maps");

//Key is pid, value is fd of relevant file
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,struct relevant_fds);
} relevant_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, char[FUNCNAME_MAX]);
	__type(value, u64);
} funcnames SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,int);
} active_write_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value,int);
} leader SEC(".maps");


//Holds the status of pids, leader, normal etc.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,int);
} nodes SEC(".maps");
