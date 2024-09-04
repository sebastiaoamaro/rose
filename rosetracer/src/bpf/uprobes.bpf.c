// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Define a BPF map to store identifiers for each uprobe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4098);
    __type(key, u64);
    __type(value, u32);
} uprobe_map SEC(".maps");

volatile int counter = 0;
volatile const int pid_counter = 0;

SEC("uprobe/my_uprobe")
int handle_uprobe(struct pt_regs *ctx) {
	
    counter++;

    return 0;
}