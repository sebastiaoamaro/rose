#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "aux.h"
#include "fs.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 128);
	__type(key, int);
	__type(value, struct fault);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faults SEC(".maps");