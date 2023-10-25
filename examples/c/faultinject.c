// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "faultinject.h"
#include "faultinject.skel.h"


static int get_int(const char *arg, int *ret, int min, int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(arg, &end, 10);
	if (errno) {
		fprintf(stderr, "strtol: %s: %s\n", arg, strerror(errno));
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}



struct faultinject_bpf* fault_inject(int faults,int timemode)
{
	struct faultinject_bpf *skel;
	int err;

	/* Load and verify BPF application */
	skel = faultinject_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return NULL;
	}

	/* Parameterize BPF code with minimum duration parameter */
	// skel->rodata->filter_pid = env.pid;
	// skel->rodata->probability = env.probability;
	// skel->rodata->syscall_idx = env.syscall_idx;
	skel->rodata->fault_count = faults;
	skel->rodata->time_only = timemode;
	/* Load & verify BPF programs */
	err = faultinject_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return NULL;
	}

	/* Attach tracepoints */
	err = faultinject_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return NULL;
	}

	return skel;
}