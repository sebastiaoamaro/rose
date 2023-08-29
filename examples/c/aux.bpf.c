#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "aux.h"
#include "fs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


//ARRAYS ARE NECESSARY AS VALUES BECAUSE DIFFERENT FAULT MIGHT HAVE THE SAME STATE PROPERTY
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct info_key);
	__type(value, struct info_state);
} relevant_state_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key,struct fault_key);
	__type(value, struct fault_description);
} faulttype SEC(".maps");

//Key is network device index, value is array of IPS to block incoming (for now)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __be32[MAX_IPS_BLOCKED]);
} blocked_ips SEC(".maps");

//Key is pid
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value,struct file_info_simple);
} files SEC(".maps");

//Key is pid, value is fd of relevant file
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value,int);
} relevant_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, char[FUNCNAME_MAX]);
	__type(value, u64);
} funcnames SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value,int);
} active_write_fd SEC(".maps");