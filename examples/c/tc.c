// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include "tc.skel.h"
#include "aux.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static struct bpf_tc_hook *tc_hook_handle;

struct bpf_tc_hook* get_tc_hook(int position){
	return &tc_hook_handle[position];
}

static struct bpf_tc_opts *tc_opts_handle;

struct bpf_tc_opts* get_tc_opts(int position){
	return &tc_opts_handle[position];
}

void init_tc(int devicecount){
	tc_hook_handle = (struct bpf_tc_hook*)malloc(devicecount*sizeof(struct bpf_tc_hook));
	tc_opts_handle = (struct bpf_tc_opts*)malloc(devicecount*sizeof(struct bpf_tc_opts));
	
}
struct tc_bpf* traffic_control(__u32 index,int fault,int faults)
{	
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		.ifindex = index, .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
		.handle = fault, .priority = 4);
	bool hook_created = false;
	struct tc_bpf *skel;
	int err;

	tc_hook_handle[fault] = tc_hook;
	tc_opts_handle[fault] = tc_opts;

	//libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return NULL;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	skel->rodata->if_index = index;

	skel->rodata->fault_count = faults;

	err = tc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return NULL;
	}

	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		return NULL;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		return NULL;
	}

	// if (signal(SIGINT, sig_int) == SIG_ERR) {
	// 	err = errno;
	// 	fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
	// }

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	// while (!exiting) {
	// 	fprintf(stderr, ".");
	// 	sleep(1);
	// }

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;

// cleanup:
// 	if (hook_created)
// 		bpf_tc_hook_destroy(&tc_hook);
// 	tc_bpf__destroy(skel);
	return skel;
}
