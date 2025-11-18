// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Google LLC.
 *
 * Based on funclatency from BCC by Brendan Gregg and others
 * 2021-02-26   Barret Rhoden   Created this.
 *
 * TODO:
 * - support uprobes on libraries without -p PID. (parse ld.so.cache)
 * - support regexp pattern matching and per-function histograms
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "uprobes.h"
#include "aux.h"
#include "uprobes.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct prog_env {
	int units;
	pid_t pid;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool timestamp;
	char *funcname;
	bool verbose;
	bool kprobes;
	char *cgroupspath;
	bool cg;
	bool is_kernel_func;
} env = {
	.interval = 99999999,
	.iterations = 99999999,
};



static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *unit_str(void)
{
	switch (env.units) {
	case NSEC:
		return "nsec";
	case USEC:
		return "usec";
	case MSEC:
		return "msec";
	};

	return "bad units";
}

// static bool try_fentry(struct uprobes_bpf *obj)
// {
// 	long err;

// 	if (env.kprobes || !env.is_kernel_func ||
// 	    !fentry_can_attach(env.funcname, NULL)) {
// 		goto out_no_fentry;
// 	}

// 	err = bpf_program__set_attach_target(obj->progs.dummy_fentry, 0,
// 					     env.funcname);
// 	if (err) {
// 		warn("failed to set attach fentry: %s\n", strerror(-err));
// 		goto out_no_fentry;
// 	}

// 	err = bpf_program__set_attach_target(obj->progs.dummy_fexit, 0,
// 					     env.funcname);
// 	if (err) {
// 		warn("failed to set attach fexit: %s\n", strerror(-err));
// 		goto out_no_fentry;
// 	}

// 	bpf_program__set_autoload(obj->progs.dummy_kprobe, false);
// 	bpf_program__set_autoload(obj->progs.dummy_kretprobe, false);

// 	return true;

// out_no_fentry:
// 	bpf_program__set_autoload(obj->progs.dummy_fentry, false);
// 	bpf_program__set_autoload(obj->progs.dummy_fexit, false);

// 	return false;
// }

// static int attach_kprobes(struct uprobes_bpf *obj)
// {
// 	obj->links.dummy_kprobe =
// 		bpf_program__attach_kprobe(obj->progs.dummy_kprobe, false,
// 					   env.funcname);
// 	if (!obj->links.dummy_kprobe) {
// 		warn("failed to attach kprobe: %d\n", -errno);
// 		return -1;
// 	}

// 	obj->links.dummy_kretprobe =
// 		bpf_program__attach_kprobe(obj->progs.dummy_kretprobe, true,
// 					   env.funcname);
// 	if (!obj->links.dummy_kretprobe) {
// 		warn("failed to attach kretprobe: %d\n", -errno);
// 		return -1;
// 	}

// 	return 0;
// }

static int attach_uprobes(struct uprobes_bpf *obj,char * binary_location,char *function,int offset)
{
	char bin_path[PATH_MAX];
	off_t func_off;
	int ret = -1;
	long err;

	if (binary_location)
		strcpy(bin_path,binary_location);
	else if(resolve_binary_path(binary_location, env.pid, bin_path, sizeof(bin_path)))
		goto out_binary;

	func_off = get_elf_func_offset(bin_path, function);
	if (func_off < 0) {
		warn("Could not find %s in %s\n", function, bin_path);
		goto out_binary;
	}


	obj->links.dummy_kprobe =
		bpf_program__attach_uprobe(obj->progs.dummy_kprobe, false,
					   env.pid, bin_path, func_off+offset);
	//printf("Injected probe for function %s at offset %d\n",function,func_off+offset);
	if (!obj->links.dummy_kprobe) {
		err = -errno;
		printf("Failed to attach uprobe: %ld\n", err);
		goto out_binary;
	}

	ret = 0;

out_binary:
	return 0;

	return ret;
}

struct uprobes_bpf* uprobe(int pid,char* funcname,char *binary_location,int faultcount,int cond_pos,int timemode, int primary_function,int offset)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);

	struct uprobes_bpf *obj;
	int i, err;
	struct tm *tm;
	char ts[32];
	time_t t;
	int idx, cg_map_fd;
	int cgfd = -1;
	bool used_fentry = false;

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return NULL;
	}

	obj = uprobes_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return NULL;
	}
	obj->rodata->fault_count = faultcount;
	obj->rodata->time_only = timemode;
	obj->rodata->units = MSEC;
	obj->rodata->cond_pos = cond_pos;
	obj->rodata->primary_function = primary_function;

	env.pid = -1;

	//used_fentry = try_fentry(obj);


	err = uprobes_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object\n");
		return NULL;
	}

	if (!obj->bss) {
		warn("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		return NULL;
	}

		err = attach_uprobes(obj,binary_location,funcname,offset);
		if (err){
			printf("Error is %d \n",err);
			return NULL;
		}

	err = uprobes_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
			strerror(-err));
			return NULL;
	}
	return obj;
}
