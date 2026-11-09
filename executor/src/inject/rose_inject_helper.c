// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Standalone helper for rose's dynamic (runtime) fault-injection mode.
//
// Everything that can be done with a plain BPF map read/write (arming a
// reserved fault slot, setting a condition threshold, polling whether a
// slot is free to reuse) is done from pure Python3 via `bpftool` against
// the already-pinned maps - see toexfi/rose_injector.py. This
// binary exists only for the two things that genuinely need a compiled
// libbpf call:
//
//   attach_uprobe  - loads and attaches a brand-new uprobe. uprobe() in
//                    uprobes.c does a full BPF skeleton open/load/attach,
//                    which has no equivalent as a bpftool one-liner. The
//                    attached link is pinned to bpffs before this process
//                    exits, so the probe keeps running independently of
//                    this short-lived process (mirrors how `executor`
//                    itself keeps every uprobe link alive for the whole
//                    run just by never closing its fd - here nothing
//                    long-lived holds the fd, so the link has to be
//                    pinned instead).
//
//   dump_layout    - prints the *actual compiled* offsetof/sizeof of the
//                    structs rose_injector.py needs to byte-pack
//                    (struct simplified_fault, info_key, info_state), so
//                    the Python side never has to hand-derive padding or
//                    alignment - it asks this binary once and caches the
//                    answer.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "aux.h"
#include "uprobes.h"
// uprobes.h only forward-declares uprobe()'s return type; the full
// definition of struct uprobes_bpf (needed below for obj->links.dummy_kprobe)
// lives in the generated skeleton, same as uprobes.c itself includes.
#include "uprobes.skel.h"
// For ensure_core_btf(), needed by attach_uprobe_file_offset() below (same
// CO-RE BTF setup uprobe() itself does in uprobes.c).
#include "btf_helpers.h"

static int cmd_dump_layout(void)
{
	printf("{\n");
	printf("  \"simplified_fault\": {\"size\": %zu, \"offsets\": {\n", sizeof(struct simplified_fault));
	printf("    \"fault_type\": %zu,\n", offsetof(struct simplified_fault, fault_type));
	printf("    \"duration\": %zu,\n", offsetof(struct simplified_fault, duration));
	printf("    \"done\": %zu,\n", offsetof(struct simplified_fault, done));
	printf("    \"start_time\": %zu,\n", offsetof(struct simplified_fault, start_time));
	printf("    \"initial\": %zu,\n", offsetof(struct simplified_fault, initial));
	printf("    \"end\": %zu,\n", offsetof(struct simplified_fault, end));
	printf("    \"pid\": %zu,\n", offsetof(struct simplified_fault, pid));
	printf("    \"target\": %zu,\n", offsetof(struct simplified_fault, target));
	printf("    \"target_if_index\": %zu,\n", offsetof(struct simplified_fault, target_if_index));
	printf("    \"repeat\": %zu,\n", offsetof(struct simplified_fault, repeat));
	printf("    \"occurrences\": %zu,\n", offsetof(struct simplified_fault, occurrences));
	printf("    \"return_value\": %zu,\n", offsetof(struct simplified_fault, return_value));
	printf("    \"faults_injected_counter\": %zu,\n", offsetof(struct simplified_fault, faults_injected_counter));
	printf("    \"relevant_conditions\": %zu,\n", offsetof(struct simplified_fault, relevant_conditions));
	printf("    \"fault_nr\": %zu,\n", offsetof(struct simplified_fault, fault_nr));
	printf("    \"run\": %zu,\n", offsetof(struct simplified_fault, run));
	printf("    \"quorum_size\": %zu,\n", offsetof(struct simplified_fault, quorum_size));
	printf("    \"faults_done\": %zu,\n", offsetof(struct simplified_fault, faults_done));
	printf("    \"corrupt_buffer\": %zu,\n", offsetof(struct simplified_fault, corrupt_buffer));
	printf("    \"timestamp\": %zu,\n", offsetof(struct simplified_fault, timestamp));
	printf("    \"claimed\": %zu,\n", offsetof(struct simplified_fault, claimed));
	printf("    \"group_leader_fault_nr\": %zu\n", offsetof(struct simplified_fault, group_leader_fault_nr));
	printf("  }},\n");
	printf("  \"faultstate_simple\": {\"size\": %zu, \"offsets\": {\n", sizeof(struct faultstate_simple));
	printf("    \"fault_type_conditions\": %zu,\n", offsetof(struct faultstate_simple, fault_type_conditions));
	printf("    \"conditions_match\": %zu,\n", offsetof(struct faultstate_simple, conditions_match));
	printf("    \"dependency_fault_nrs\": %zu,\n", offsetof(struct faultstate_simple, dependency_fault_nrs));
	printf("    \"dependency_satisfied\": %zu\n", offsetof(struct faultstate_simple, dependency_satisfied));
	printf("  }},\n");
	printf("  \"info_key\": {\"size\": %zu, \"offsets\": {\"pid\": %zu, \"infotype\": %zu}},\n",
	       sizeof(struct info_key), offsetof(struct info_key, pid), offsetof(struct info_key, infotype));
	printf("  \"info_state\": {\"size\": %zu, \"offsets\": {\"relevant_states\": %zu, \"current_value\": %zu, \"repeat\": %zu}},\n",
	       sizeof(struct info_state), offsetof(struct info_state, relevant_states),
	       offsetof(struct info_state, current_value), offsetof(struct info_state, repeat));
	printf("  \"constants\": {\"STATE_PROPERTIES_COUNT\": %d, \"MAX_FUNCTIONS\": %d, \"MAX_FAULT_DEPS\": %d, \"MAX_FAULTS\": %d, \"MAP_SIZE\": %d},\n",
	       STATE_PROPERTIES_COUNT, MAX_FUNCTIONS, MAX_FAULT_DEPS, MAX_FAULTS, MAP_SIZE);
	// schedule_parser/conditions.py's get_cond_type_nr() and
	// schedule_parser/faults.py's get_fault_type_nr() return a plain int
	// for some names and, for others, the C macro NAME itself (meant for
	// C codegen, resolved only at compile time) - these two maps let
	// rose_injector.py resolve any such name back to its real integer
	// value, straight from bpf_shared.h's own enums, instead of hand
	// -copying (and risking drifting from) the constants.
	printf("  \"stateinfo\": {\n");
	printf("    \"WRITES\": %d, \"READS\": %d, \"OPENS\": %d, \"TIME_STATE\": %d,\n", WRITES, READS, OPENS, TIME_STATE);
	printf("    \"NEWFSTATAT_STATE\": %d, \"OPENNAT_STATE\": %d, \"OPENAT_SPECIFIC\": %d,\n", NEWFSTATAT_STATE, OPENNAT_STATE, OPENAT_SPECIFIC);
	printf("    \"FDATASYNC_STATE\": %d, \"FSYNC_STATE\": %d, \"PWRITE64_STATE\": %d,\n", FDATASYNC_STATE, FSYNC_STATE, PWRITE64_STATE);
	printf("    \"ACCEPT_STATE\": %d, \"CLOSE_STATE\": %d, \"FUTEX_STATE\": %d, \"CONNECT_STATE\": %d,\n", ACCEPT_STATE, CLOSE_STATE, FUTEX_STATE, CONNECT_STATE);
	printf("    \"STAT_STATE\": %d, \"LSTAT_STATE\": %d, \"RENAME_STATE\": %d, \"LSEEK_STATE\": %d,\n", STAT_STATE, LSTAT_STATE, RENAME_STATE, LSEEK_STATE);
	printf("    \"UNLINK_STATE\": %d, \"SYNC_FILE_RANGE_STATE\": %d, \"BIND_STATE\": %d,\n", UNLINK_STATE, SYNC_FILE_RANGE_STATE, BIND_STATE);
	printf("    \"ACCEPT4_STATE\": %d\n", ACCEPT4_STATE);
	printf("  },\n");
	printf("  \"fault_type\": {\n");
	printf("    \"WRITE\": %d, \"READ\": %d, \"FSYNC_FAULT\": %d, \"FDATASYNC_FAULT\": %d,\n", WRITE, READ, FSYNC_FAULT, FDATASYNC_FAULT);
	printf("    \"PWRITE64_FAULT\": %d, \"ACCEPT_FAULT\": %d, \"CONNECT_FAULT\": %d,\n", PWRITE64_FAULT, ACCEPT_FAULT, CONNECT_FAULT);
	printf("    \"STAT_FAULT\": %d, \"LSTAT_FAULT\": %d, \"RENAME_FAULT\": %d, \"UNLINK_FAULT\": %d,\n", STAT_FAULT, LSTAT_FAULT, RENAME_FAULT, UNLINK_FAULT);
	printf("    \"SYNC_FILE_RANGE_FAULT\": %d, \"BIND_FAULT\": %d, \"OPEN\": %d, \"MKDIR\": %d,\n", SYNC_FILE_RANGE_FAULT, BIND_FAULT, OPEN, MKDIR);
	printf("    \"FDATASYNC_RET_FAULT\": %d, \"PARTIAL_WRITE_FAULT\": %d, \"PARTIAL_READ_FAULT\": %d, \"TORN_READ_FAULT\": %d,\n",
	       FDATASYNC_RET_FAULT, PARTIAL_WRITE_FAULT, PARTIAL_READ_FAULT, TORN_READ_FAULT);
	printf("    \"ACCEPT4_FAULT\": %d\n", ACCEPT4_FAULT);
	printf("  }\n");
	printf("}\n");
	return 0;
}

static int cmd_attach_uprobe(int argc, char **argv)
{
	// attach_uprobe <pid> <funcname> <binary_location> <fault_count> <cond_pos> <mode> <primary_function> <offset> <absolute_offset> <pin_path>
	if (argc != 12) {
		fprintf(stderr,
			"usage: %s attach_uprobe <pid> <funcname> <binary_location> <fault_count> "
			"<cond_pos> <mode> <primary_function> <offset> <absolute_offset> <pin_path>\n",
			argv[0]);
		return 2;
	}
	int pid = atoi(argv[2]);
	char *funcname = argv[3];
	char *binary_location = argv[4];
	int fault_count = atoi(argv[5]);
	int cond_pos = atoi(argv[6]);
	int mode = atoi(argv[7]);
	int primary_function = atoi(argv[8]);
	int offset = atoi(argv[9]);
	int absolute_offset = atoi(argv[10]);
	char *pin_path = argv[11];

	bump_memlock_rlimit();

	struct uprobes_bpf *obj = uprobe(pid, funcname, binary_location, fault_count,
					  cond_pos, mode, primary_function, offset, absolute_offset);
	if (!obj) {
		fprintf(stderr, "attach_uprobe: failed to attach uprobe for symbol='%s' binary='%s'\n",
			funcname, binary_location);
		return 1;
	}

	// Pin the link so the attached probe survives this short-lived
	// process exiting - nothing else keeps its fd open. Pinning the link
	// also keeps the BPF program it points at loaded (the kernel-side
	// link holds a reference to the program), so this one call is
	// enough; no separate program pin is needed.
	int err = bpf_link__pin(obj->links.dummy_kprobe, pin_path);
	if (err) {
		fprintf(stderr, "attach_uprobe: failed to pin link at '%s': %d\n", pin_path, err);
		return 1;
	}

	printf("OK\n");
	return 0;
}

// attach_uprobe_file_offset: like attach_uprobe, but for a condition whose
// offset is ALREADY a resolved ELF *file* offset (binary_analysis/
// protocol_states' resolve_offsets.py output, e.g. functions.txt's
// "name,offset" pairs - confirmed by reading resolve_offsets.py directly:
// it converts a DWARF virtual address to a file offset itself via
// vaddr_to_file_offset() and writes THAT, not the vaddr). Neither of
// uprobe()'s two existing modes fits this: absolute_offset=true treats
// `offset` as a virtual address needing its own vaddr->file-offset
// conversion (double-converts an already-file-offset value, landing on
// a wrong-but-plausible .text address - confirmed empirically: it
// attached without error but the probe never fired under real load);
// absolute_offset=false does its own independent ELF *symbol-table*
// lookup by name (get_elf_func_offset()), which fails outright for a Go
// binary's short/unqualified symbol names (e.g. "Send" instead of its
// real qualified symbol) - confirmed empirically too ("Could not find
// Send in ..."). This mode skips both: attach directly at the given
// file offset, exactly like resolve_offsets.py's own consumer
// (binary_analysis/protocol_states' tracer) already does.
static int cmd_attach_uprobe_file_offset(int argc, char **argv)
{
	// attach_uprobe_file_offset <pid> <binary_location> <file_offset> <fault_count> <cond_pos> <mode> <primary_function> <pin_path>
	if (argc != 10) {
		fprintf(stderr,
			"usage: %s attach_uprobe_file_offset <pid> <binary_location> <file_offset> "
			"<fault_count> <cond_pos> <mode> <primary_function> <pin_path>\n",
			argv[0]);
		return 2;
	}
	int pid = atoi(argv[2]);
	char *binary_location = argv[3];
	long file_offset = atol(argv[4]);
	int fault_count = atoi(argv[5]);
	int cond_pos = atoi(argv[6]);
	int mode = atoi(argv[7]);
	int primary_function = atoi(argv[8]);
	char *pin_path = argv[9];
	(void)pid; // uprobe() itself always attaches with pid=-1 (all processes) and
	           // relies on the shared pid_tree map for filtering - kept as a
	           // parameter only for symmetry/future use, same as uprobe()'s own.

	bump_memlock_rlimit();

	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	int err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "attach_uprobe_file_offset: failed to fetch CO-RE BTF: %s\n", strerror(-err));
		return 1;
	}

	struct uprobes_bpf *obj = uprobes_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "attach_uprobe_file_offset: failed to open BPF object\n");
		return 1;
	}
	obj->rodata->fault_count = fault_count;
	obj->rodata->mode = mode;
	obj->rodata->units = MSEC;
	obj->rodata->cond_pos = cond_pos;
	obj->rodata->primary_function = primary_function;

	if (uprobes_bpf__load(obj)) {
		fprintf(stderr, "attach_uprobe_file_offset: failed to load BPF object\n");
		return 1;
	}
	if (!obj->bss) {
		fprintf(stderr, "attach_uprobe_file_offset: BPF global data (bss) not mapped\n");
		return 1;
	}

	// pid=-1: same as uprobe()'s own attach_uprobes() - rose filters by
	// pid_tree, not by the uprobe attachment's own pid filter.
	obj->links.dummy_kprobe = bpf_program__attach_uprobe(obj->progs.dummy_kprobe, false, -1,
							       binary_location, file_offset);
	if (!obj->links.dummy_kprobe) {
		fprintf(stderr, "attach_uprobe_file_offset: failed to attach at file offset %ld in '%s': %d\n",
			file_offset, binary_location, -errno);
		return 1;
	}

	if (uprobes_bpf__attach(obj)) {
		fprintf(stderr, "attach_uprobe_file_offset: failed to attach BPF programs\n");
		return 1;
	}

	int pin_err = bpf_link__pin(obj->links.dummy_kprobe, pin_path);
	if (pin_err) {
		fprintf(stderr, "attach_uprobe_file_offset: failed to pin link at '%s': %d\n", pin_path, pin_err);
		return 1;
	}

	printf("OK\n");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <dump_layout|attach_uprobe|attach_uprobe_file_offset ...>\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "dump_layout"))
		return cmd_dump_layout();
	if (!strcmp(argv[1], "attach_uprobe"))
		return cmd_attach_uprobe(argc, argv);
	if (!strcmp(argv[1], "attach_uprobe_file_offset"))
		return cmd_attach_uprobe_file_offset(argc, argv);

	fprintf(stderr, "unknown subcommand '%s'\n", argv[1]);
	return 2;
}
