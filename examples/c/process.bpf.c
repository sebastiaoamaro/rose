// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process.h"
#include "aux.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64[512]);
	 __uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_state_info SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exit_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;
const volatile int fault_count = 0;

static u64 processes_created = 0;
static u64 processes_exited = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{

	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* successfully submit it to user-space for post-processing */
	//bpf_ringbuf_submit(e, 0);

	u64 opened = PROCESSES_OPENED;
	u64* processes_opened = bpf_map_lookup_elem(&relevant_state_info,&opened);
	//bpf_printk("In open \n");
	if (processes_opened){

		for (int i=0;i<fault_count;i++){
			//bpf_printk("processes_opened_state is %llu and processes_created is %llu \n", processes_opened[i],processes_created);
			if (processes_opened[i] == processes_created && processes_opened[i] != 0){
				/* reserve sample from BPF ringbuf */
				e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
				if (!e)
					return 0;

				/* fill out the sample with data */
				task = (struct task_struct *)bpf_get_current_task();

				e->type = EXEC_EXIT;
				e->pid = pid;
				e->ppid = BPF_CORE_READ(task, real_parent, tgid);
				e->processes_created = processes_created;
				bpf_get_current_comm(&e->comm, sizeof(e->comm));

				fname_off = ctx->__data_loc_filename & 0xFFFF;
				bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

				bpf_printk("Sent to userspace \n");
				bpf_ringbuf_submit(e, 0);
				processes_created+=1;
				return 0;
			}
		}
		//If it is not relevant to the states we want discard it
		//bpf_printk("Skipped \n");
		processes_created+=1;
		return 0;
		
		bpf_map_update_elem(&exec_map, &ts, &e, BPF_ANY);
	}
	
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;
	
	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* send data to user-space for post-processing */
	//bpf_ringbuf_submit(e, 0);

	u64 closed = PROCESSES_CLOSED;
	u64* processes_closed = bpf_map_lookup_elem(&relevant_state_info,&closed);
	//bpf_printk("In close \n");
	if (processes_closed){

		for (int i=0;i<2;i++){
			//bpf_printk("processes_closed_state is %llu and processes_exited is %llu \n", processes_closed[i],processes_exited);
			if (processes_closed[i] == processes_exited && processes_closed[i] != 0) {

					/* reserve sample from BPF ringbuf */
				e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
				if (!e)
					return 0;

				/* fill out the sample with data */
				task = (struct task_struct *)bpf_get_current_task();

				e->type = EXEC_EXIT;
				e->duration_ns = duration_ns;
				e->pid = pid;
				e->ppid = BPF_CORE_READ(task, real_parent, tgid);
				e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
				e->processes_closed = processes_exited;
				bpf_get_current_comm(&e->comm, sizeof(e->comm));

				bpf_printk("Sent to userspace \n");
				bpf_ringbuf_submit(e, 0);
				processes_exited+=1;
				return 0;
			}
		}
		//If it is not relevant to the states we want discard it
		//bpf_printk("Skipped \n");
		processes_exited+=1;
		return 0;
		
		bpf_map_update_elem(&exec_map, &ts, &e, BPF_ANY);
	}

	return 0;
}

