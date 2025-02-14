// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on vfsstat(8) from BCC by Brendan Gregg


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include "vfsstat.h"
#include "aux.h"
__u64 stats[S_MAXSTAT] = {};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct vfs_data_t);
} read_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct vfs_data_t);
} write_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct vfs_data_t);
} fsync_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct vfs_data_t);
} open_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct vfs_data_t);
} create_map SEC(".maps");


const volatile pid_t filter_pid = 0;

static __always_inline int inc_stats(int key)
{
	__atomic_add_fetch(&stats[key], 1, __ATOMIC_RELAXED);
	return 0;
}

static void get_file_path(struct file *file, char *buf, size_t size)
{
	struct qstr dname;

	dname = BPF_CORE_READ(file, f_path.dentry, d_name);
	bpf_probe_read_kernel(buf, size, dname.name);
}



static __always_inline int
trace(u32 pid, int size, int type,struct file *file)
{
    struct event_vfsstat *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 1;

	e->pid = pid;
	e->size = size;
	e->type = type;
	get_file_path(file,e->name,sizeof(e->name));

	//e->type = "READ";
	//bpf_get_current_comm(&ss_data.comm, sizeof(ss_data.comm));
	//strncpy(&e->type, "READ", sizeof(e->type));

	//isto está no ebpfsnitch ... 
	//bpf_probe_read(&l_sock, sizeof(l_sock), &l_socket->sk)

	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read, struct file *file, void *buf, size_t size)
{
    // EVAL
    u64 start = bpf_ktime_get_ns();

    
    u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (filter_pid && pid != filter_pid) {
		return 0;
	}


	trace(pid, (int) size, 0,file);
	
	//add to map
	//struct vfs_data_t vfs_data = {.pid = pid, .size = size, .type = 0};
	//bpf_map_update_elem(&read_map, &stats[S_READ], &vfs_data, 0 /* flags: BPF_ANY */);

    // EVAL
    //bpf_printk("READ %d\n", bpf_ktime_get_ns() - start);

	return inc_stats(S_READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write, struct file *file, void *buf, size_t size)
{
    // EVAL
    u64 start = bpf_ktime_get_ns();

    
    u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (filter_pid && pid != filter_pid) {
		return 0;
	}

	trace(pid, (int) size, 1,file);
	//add to map
	// struct vfs_data_t vfs_data = {.pid = pid, .size = size, .type = 1};
	// bpf_map_update_elem(&write_map, &stats[S_WRITE], &vfs_data, 0 /* flags: BPF_ANY */);

    // // EVAL
    // bpf_printk("WRITE %d\n", bpf_ktime_get_ns() - start);

	return inc_stats(S_WRITE);
}

SEC("kprobe/vfs_fsync")
int BPF_KPROBE(vfs_fsync, struct file *file, int datasync)
//datasync maybe a bool to be sure that was really synced
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (filter_pid && pid != filter_pid) {
		return 0;
	}
	trace(pid, 0, 2,file);
	//add to map
	// struct vfs_data_t vfs_data = {.pid = pid, .size = 0, .type = 2};
	// bpf_map_update_elem(&fsync_map, &stats[S_FSYNC], &vfs_data, 0 /* flags: BPF_ANY */);

	return inc_stats(S_FSYNC);
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file)
{
    // EVAL
    u64 start = bpf_ktime_get_ns();

    u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (filter_pid && pid != filter_pid) {
		return 0;
	}

	trace(pid, 0, 3,file);
	//add to map
	// struct vfs_data_t vfs_data = {.pid = pid, .size = 0, .type = 3};
	// bpf_map_update_elem(&open_map, &stats[S_OPEN], &vfs_data, 0 /* flags: BPF_ANY */);

    // EVAL
    bpf_printk("OPEN %d\n", bpf_ktime_get_ns() - start);

	return inc_stats(S_OPEN);
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(vfs_create, struct inode *dir, struct dentry *dentry,
		umode_t mode, bool want_excl)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (filter_pid && pid != filter_pid) {
		return 0;
	}



	//trace(pid, 0, 4,file);

	//add to map
	struct vfs_data_t vfs_data = {.pid = pid, .size = 0, .type = 4};
	bpf_map_update_elem(&create_map, &stats[S_CREATE], &vfs_data, 0 /* flags: BPF_ANY */);

	return inc_stats(S_CREATE);
}

char LICENSE[] SEC("license") = "GPL";