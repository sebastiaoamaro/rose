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
#include <stdbool.h>
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

static int attach_uprobes(struct uprobes_bpf *obj,char * binary_location,char *function,int offset, int absolute_offset)
{
	char bin_path[PATH_MAX];
	off_t func_off;
	int ret = -1;
	long err;
	if (binary_location)
		strcpy(bin_path,binary_location);
	else if(resolve_binary_path(binary_location, env.pid, bin_path, sizeof(bin_path)))
		goto out_binary;

	if (absolute_offset){
		/* vaddr->file-offset fix: bpf_program__attach_uprobe needs a file offset,
		 * but `offset` is a virtual address from DWARF. Convert via PT_LOAD.
*          This is relevant for non-pie binaries, there might be cases where we can not rebuild. */
		int efd = -1;
		Elf *e = open_elf(bin_path, &efd);
		func_off = -1;
		if (e) {
			size_t nhdrs;
			GElf_Phdr phdr;
			if (elf_getphdrnum(e, &nhdrs) == 0) {
				for (int k = 0; k < (int)nhdrs; k++) {
					if (!gelf_getphdr(e, k, &phdr)) continue;
					if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X)) continue;
					if (phdr.p_vaddr <= (GElf_Addr)offset &&
					    (GElf_Addr)offset < phdr.p_vaddr + phdr.p_memsz) {
						func_off = offset - phdr.p_vaddr + phdr.p_offset;
						break;
					}
				}
			}
			close_elf(e, efd);
		}
		if (func_off < 0) {
			warn("vaddr 0x%x not found in executable PT_LOAD of %s\n", offset, bin_path);
			goto out_binary;
		}
		offset = 0;
		/* end fix */
	}else{
    	func_off = get_elf_func_offset(bin_path, function);
    	if (func_off < 0) {
    		warn("Could not find %s in %s\n", function, bin_path);
    		goto out_binary;
    	}
	}

	obj->links.dummy_kprobe = bpf_program__attach_uprobe(obj->progs.dummy_kprobe, false, env.pid, bin_path, func_off+offset);
	if (!obj->links.dummy_kprobe) {
		err = -errno;
		printf("Failed to attach uprobe: %ld\n", err);
		goto out_binary;
	}

	ret = 0;

out_binary:
	return ret;
}

struct uprobes_bpf* uprobe(int pid,char* funcname,char *binary_location,int faultcount,int cond_pos,int timemode, int primary_function,int offset, int absolute_offset)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);

	struct uprobes_bpf *obj;
	int err;

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
	obj->rodata->mode = timemode;
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

		err = attach_uprobes(obj,binary_location,funcname,offset,absolute_offset);
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
