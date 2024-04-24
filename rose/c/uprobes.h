/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#pragma once

#define MAX_PIDS 102400
#define MAX_SLOTS 25

enum units {
	NSEC,
	USEC,
	MSEC,
};

struct uprobes_bpf* uprobe(int pid,char* funcname,char* binary_location, int faultcount,int cond_pos,int time_mode);