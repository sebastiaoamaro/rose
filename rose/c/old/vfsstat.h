// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
#ifndef __VFSSTAT_H
#define __VFSSTAT_H

#define NUMBER_STRINGS 4096
#define STRING_MAX_SIZE 100
enum stat_types {
	S_READ,
	S_WRITE,
	S_FSYNC,
	S_OPEN,
	S_CREATE,
	S_MAXSTAT,
};

struct event_vfsstat {
	__u32 pid;
	int size;
	__u32 type;
	char name[4096];
};

struct vfs_data_t {
	__u32 pid;
	int size;
	__u32 type;
	//const unsigned char *name;
};

int vfsstat();
#endif /* __VFSSTAT_H */