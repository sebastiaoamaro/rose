// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "aux.h"
#include "process.h"
#include "process.skel.h"
#include <pthread.h>

static struct env {
	bool verbose;
	long min_duration_ms;
} env;


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

struct process_bpf* exec_and_exit(int faults){

	struct process_bpf *skel;

	int err;

		/* Load and verify BPF application */
	skel = process_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return NULL;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
	skel->rodata->fault_count = faults;
	/* Load & verify BPF programs */
	err = process_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return NULL;
	}

	/* Attach tracepoints */
	err = process_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return NULL;
	}

	return skel;

}