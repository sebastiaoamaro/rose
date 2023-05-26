#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "block.h"
#include "block.skel.h"

struct block_bpf* monitor_disk(){
    struct block_bpf *skel;

    int err;

    /* Load and verify BPF application */
    skel = block_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return NULL;
    }

    /* Parameterize BPF code with minimum duration parameter */
    // skel->rodata->filter_pid = env.pid;
    // skel->rodata->probability = env.probability;
    // skel->rodata->syscall_idx = env.syscall_idx;

    /* Load & verify BPF programs */
    err = block_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return NULL;
    }

    /* Attach tracepoints */
    err = block_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return NULL;
    }

    return skel;
}