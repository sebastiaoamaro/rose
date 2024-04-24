/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __FAULTINJECT_H
#define __FAULTINJECT_H

#define MAX_INT 4294967296

struct sys_info {
	int fd;
	int general_syscall_code;
	int file_specific_code;
	int general_fault_code;
	int file_specific_fault_code;
	int fault_count;
	int time_only;
};

struct maps {
	struct bpf_map *relevant_state_info;
	struct bpf_map *faults_specification;
	struct bpf_map *faults;
	struct bpf_map *rb;
	struct bpf_map *files;
	struct bpf_map *relevant_fd;
};

struct faultinject_bpf* fault_inject(int faults,int timemode);

#endif /* __FAULTINJECT_H */
