// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "fault_inject.h"
#include "fault_inject.skel.h"

struct fault_inject_bpf* fault_inject(int faults,int timemode)
{
	struct fault_inject_bpf *skel;
	int err;

	/* Load and verify BPF application */
	skel = fault_inject_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return NULL;
	}
	skel->rodata->fault_count = faults;
	skel->rodata->time_only = timemode;
	/* Load & verify BPF programs */
	err = fault_inject_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return NULL;
	}

	/* Attach tracepoints */
	err = fault_inject_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return NULL;
	}

	// char binary_path[] = "/usr/lib/jvm/java-11-openjdk-amd64/lib/server/libjvm.so";
	// // err = get_jvmso_path(binary_path,pid);
	// // 	if (err){
	// // 	    printf("Failed to get JVM path\n");
	// // 		return NULL;
	// // 	}
	// printf("Binary path: %s\n", binary_path);

	// skel->links.entry_probe = bpf_program__attach_usdt(skel->progs.entry_probe, -1,binary_path, "hotspot", "method__entry", NULL);

	// if (!skel->links.entry_probe) {
	// 	err = errno;
	// 	printf("attach usdt method__entry failed: %s\n", strerror(err));
	// 	return NULL;
	// }

	return skel;
}
