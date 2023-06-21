// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "faultinject.h"
#include "aux.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct fault_key);
	__type(value, struct fault_description);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faulttype SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct info_key);
	__type(value, struct info_state);
	 __uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_state_info SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, int);
    __type(value, int);
} pids SEC(".maps");

const volatile int fault_count = 0;

static __always_inline
int send_event()
{
	struct event_faultinject *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 1;
	
	e->injected = 1;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

static __always_inline
bool filter_pids()
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	int key = 0;
	int *v;
	int len;

	v = bpf_map_lookup_elem(&pids, &key);
	if (v) {
		len = (int)*v;
		if(len == 0) {
			return false;
		}
		bpf_printk("len = pids[0] = %d\n", len);
	}

	int val;
    // at max, loop will have 3 iterations
	// loops are not available on ebpf (to avoid infinite loops)
	// thus I manually unrolled the for-loop
	int i = 1;
	if(len >= 1) {
		v = bpf_map_lookup_elem(&pids, &i);
		if (v) {
			val = (int)*v;
			bpf_printk("len = 1 = %d\n", len);
			if(pid == val) {
				return true;
			}
			bpf_printk("passed len = 1 = %d\n", len);
		}
	}
	i++;
	if(len >= 2) {
		v = bpf_map_lookup_elem(&pids, &i);
		if (v) {
			val = (int)*v;

			bpf_printk("len = 2 \n");
			if(pid == val) {
				return true;
			}
			bpf_printk("passed len = 2\n");
		}
	}
	i++;
	if(len >= 3) {
		v = bpf_map_lookup_elem(&pids, &i);
		if (v) {
			val = (int)*v;

			bpf_printk("len = 3 \n");
			if(pid == val) {
				return true;
			}
			bpf_printk("passed len = 3\n");
		}
	}

	return false;
}

static __always_inline
int fault_injection(struct pt_regs *ctx)
{

    return 0;
}

static u64 writes_blocked = 0;
static u64 reads_blocked = 0;
static u64 threads_blocked = 0;

static inline int process_current_state(int state_key, int type, int pid){

	struct info_key information = {
		pid,
		state_key
	};

	struct info_state *current_state;

	current_state = bpf_map_lookup_elem(&relevant_state_info,&information);
	
	if (current_state){
		//bpf_printk("Found write in pid %d \n",pid);

		current_state->current_value++;
		u64 value = current_state->current_value;
		if(current_state->relevant_states){
			for (int i=0;i<fault_count;i++){
				if (current_state->relevant_states[i]){
					u64 relevant_value = current_state->relevant_states[i];
					if (relevant_value == value && relevant_value != 0){

						struct event *e;

						/* reserve sample from BPF ringbuf */
						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
						if (!e)
							return 0;

						e->type = type;
						e->pid = pid;
						e->state_condition = value;
						bpf_ringbuf_submit(e, 0);
						return 0;
					}
					if(current_state->repeat && (value % relevant_value == 0)){
						struct event *e;

						/* reserve sample from BPF ringbuf */
						e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
						if (!e)
							return 0;

						e->type = type;
						e->pid = pid;
						e->state_condition = relevant_value;
						bpf_ringbuf_submit(e, 0);
						return 0;
					}
					//bpf_printk("Skipped \n");
					}
					return 0;
				}
				
		}
	}
}


SEC("kprobe/__x64_sys_clone")
int BPF_KPROBE(clone)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	// if (pid == 74705)
	//bpf_printk("Tid is %u and pid is %u \n",tid,pid);

	struct fault_key fault_to_inject = {
		pid,
		CLONE,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);


	if (description_of_fault){
		if (description_of_fault->on){
			if (threads_blocked < description_of_fault->occurences){
				threads_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, -1);
			}
			else if(description_of_fault->occurences == 0){
				bpf_override_return((struct pt_regs *) ctx, -1);

			}
			else{
				threads_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(THREADS_CREATED,THREAD,pid);

	return 0;
}
SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(__x64_sys_write)
{

	// bpf_printk("%u \n",fd);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	// if (pid == 74705)
	//bpf_printk("Tid is %u and pid is %u \n",tid,pid);

	struct fault_key fault_to_inject = {
		pid,
		WRITE,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);


	if (description_of_fault){
		if (description_of_fault->on){
			if (writes_blocked < description_of_fault->occurences){
				writes_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, -1);
			}
			else if(description_of_fault->occurences == 0){
				bpf_override_return((struct pt_regs *) ctx, -1);

			}
			else{
				writes_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(WRITES,WRITE_HOOK,pid);
	

	return 0;
}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(__x64_sys_read)
{
	//safe so if other ebpf runs it does not change this value

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	// if (pid == 74705)
	//bpf_printk("Tid is %u and pid is %u \n",tid,pid);

	struct fault_key fault_to_inject = {
		pid,
		READ,
	};

	struct fault_description *description_of_fault;

	description_of_fault = bpf_map_lookup_elem(&faulttype,&fault_to_inject);

	if (description_of_fault){
		if (description_of_fault->on){
			if (reads_blocked < description_of_fault->occurences){
				reads_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, -1);
			}
			else if(description_of_fault->occurences == 0){
				bpf_override_return((struct pt_regs *) ctx, -1);

			}
			else{
				reads_blocked = 0;
				description_of_fault->on = 0;
			}
		}
	}

	int result = process_current_state(READS,READ_HOOK,pid);

	return 0;
}

SEC("kprobe/__x64_sys_sendmsg")
int BPF_KPROBE(__x64_sys_sendmsg, int sockfd, const struct msghdr *msg, int flags)
{
	// tentativa 1
	// u32 pid = bpf_get_current_pid_tgid() >> 32;
	// if (filter_pid && pid != filter_pid) {
	// 	return 0;
	// }
	// /*u32 src_addr_ipv4;
	// u32 ipv4_convert;
	// u32 dest_addr_ipv4;
	// int family;

	// struct sock *sk;


    // BPF_CORE_READ_INTO(&sk, socket, sk); // sk = sock->sk

    // BPF_CORE_READ_INTO(&family,  sk, __sk_common.skc_family);
    // BPF_CORE_READ_INTO(&src_addr_ipv4,  sk, __sk_common.skc_rcv_saddr);
    // BPF_CORE_READ_INTO(&dest_addr_ipv4, sk, __sk_common.skc_daddr);
	// //ipv4_convert = bpf_ntohl(src_addr_ipv4);

	// //int len2 = msg->msg_namelen;*/

    // struct sockaddr_in addr;
    // socklen_t addr_size = sizeof(struct sockaddr_in);
    // int res = getpeername(sockfd, (struct sockaddr *)&addr, &addr_size);
    // //char *clientip = char[20];
    // //strcpy(clientip, inet_ntoa(addr.sin_addr));

	// //int srcaddr = addr.sin_addr.s_addr;
    


	// //BPF_CORE_READ_INTO(&x, msg, msg_namelen); // sk = sock->sk

	/* tentativa 2
	struct socket *sock;
	int err2, fput_needed;
	sock = sockfd_lookup_light(sockfd, &err2, &fput_needed);

	int src_addr = socket_getpeername(sock);*/

	// if(syscall_idx != 2) {
	// 	return 0;
	// }
	// int err = fault_injection(ctx);
	// if(err) {
	// 	return -1;
	// }

	return 0;
}

SEC("kprobe/__x64_sys_recvmsg")
int BPF_KPROBE(__x64_sys_recvmsg)
{
	// if(syscall_idx != 2) {
	// 	return 0;
	// }
	// int err = fault_injection(ctx);
	// if(err) {
	// 	return -1;
	// }

	return 0;
}