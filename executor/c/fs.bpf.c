#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs.h"
#include "aux.h"
#include "fs.bpf.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";