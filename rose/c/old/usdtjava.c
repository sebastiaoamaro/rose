/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Copyright (c) 2022 Chen Tao
 * Based on ugc from BCC by Sasha Goldshtein
 * Create: Wed Jun 29 16:00:19 2022
 */
#include <stdio.h>
#include <ctype.h>
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include "usdtjava.skel.h"
#include "usdtjava.h"

#define BINARY_PATH_SIZE (256)
#define PERF_BUFFER_PAGES (32)
#define PERF_POLL_TIMEOUT_MS (200)

static struct env {
	pid_t pid;
	int time;
	bool exiting;
	bool verbose;
} env = {
	.pid = -1,
	.time = 1000,
	.exiting = false,
	.verbose = false,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && ! env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	env.exiting = true;
}

static int get_jvmso_path(char *path, int pid)
{
	char mode[16], line[128], buf[64];
	size_t seg_start, seg_end, seg_off;
	FILE *f;
	int i = 0;

	sprintf(buf, "/proc/%d/maps", pid);
	f = fopen(buf, "r");
	if (!f)
		return -1;

	while (fscanf(f, "%zx-%zx %s %zx %*s %*d%[^\n]\n",
			&seg_start, &seg_end, mode, &seg_off, line) == 5) {
		i = 0;
		while (isblank(line[i]))
			i++;
		if (strstr(line + i, "libjvm.so")) {
			break;
		}
	}

	strcpy(path, line + i);
	fclose(f);

	return 0;
}

struct javagc_bpf* usdtjava(int pid,int faultcount,int timemode)
{
	char binary_path[BINARY_PATH_SIZE] = {0};
	struct usdtjava_bpf *skel = NULL;
	int err;
	struct perf_buffer *pb = NULL;

	/*
	* libbpf will auto load the so if it in /usr/lib64 /usr/lib etc,
	* but the jvmso not there.
	*/
	err = get_jvmso_path(binary_path,pid);
	if (err)
		return err;

	skel = usdtjava_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->bss->time = env.time * 1000;

	err = usdtjava_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return NULL;
	}
	printf("PID IS %d and binary_path is %s \n",pid,binary_path);

	skel->links.handle_mem_pool_gc_start = bpf_program__attach_usdt(skel->progs.handle_gc_start, pid,
									binary_path, "hotspot", "mem__pool__gc__begin", NULL);
	if (!skel->links.handle_mem_pool_gc_start) {
		err = errno;
		fprintf(stderr, "attach usdt mem__pool__gc__begin failed: %s\n", strerror(err));

	}

	// skel->links.handle_mem_pool_gc_end = bpf_program__attach_usdt(skel->progs.handle_gc_end, pid,
	// 							binary_path, "hotspot", "mem__pool__gc__end", NULL);
	// if (!skel->links.handle_mem_pool_gc_end) {
	// 	err = errno;
	// 	fprintf(stderr, "attach usdt mem__pool__gc__end failed: %s\n", strerror(err));

	// }

	// skel->links.handle_gc_start = bpf_program__attach_usdt(skel->progs.handle_gc_start, pid,
	// 								binary_path, "hotspot", "gc__begin", NULL);
	// if (!skel->links.handle_gc_start) {
	// 	err = errno;
	// 	fprintf(stderr, "attach usdt gc__begin failed: %s\n", strerror(err));

	// }

	// skel->links.handle_gc_end = bpf_program__attach_usdt(skel->progs.handle_gc_end, pid,
	// 			binary_path, "hotspot", "gc__end", NULL);
	// if (!skel->links.handle_gc_end) {
	// 	err = errno;
	// 	fprintf(stderr, "attach usdt gc__end failed: %s\n", strerror(err));

	// }


	return skel;
}