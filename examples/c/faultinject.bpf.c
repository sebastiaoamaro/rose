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
	__type(key, int);
	__type(value, int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} syscalls_to_fail SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64[512]);
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
	int err;

	// if(!filter_pids()) {
	// 	return 0;
	// }

	// if(probability == 100) {
	// 	err = send_event();
	// 	if(err) {
	// 		return -1;
	// 	}
    // 	bpf_override_return(ctx, -1);
	// }
	// else {		
	// 	if(bpf_get_prandom_u32() < MAX_INT/100*probability) {
	// 		err = send_event();
	// 		if(err) {
	// 			return -1;
	// 		}
	// 		bpf_override_return(ctx, -1);
	// 	}
	// }

    return 0;
}

static u64 writes = 0;
static u64 reads = 0;
static u64 writes_blocked = 0;
static u64 reads_blocked = 0;

struct data_t{
	u64 fd;
};

SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(__x64_sys_write)
{
	//safe so if other ebpf runs it does not change this value

	// uint fd = PT_REGS_PARM1_CORE_SYSCALL(ctx);

	// struct data_t data = {};

	// bpf_probe_read_user(data.fd,sizeof(data.fd),(void *)&PT_REGS_PARM1(ctx));

	int fd = PT_REGS_PARM1(ctx);

	// bpf_printk("%d \n",fd);

	// if (!fd)
	// 	return 0;

	// bpf_printk("%u \n",fd);
	
	u64 pid;

	pid = bpf_get_current_pid_tgid();

	int writes_now = writes;

	int write_syscall = WRITE;

	int* inject = bpf_map_lookup_elem(&syscalls_to_fail,&write_syscall);

	if (inject){
		if (*inject){
			if (writes_blocked < 10){
				bpf_printk("Blocked write %d \n",writes_blocked);
				writes_blocked+=1;
				bpf_override_return((struct pt_regs *) ctx, -1);
			}
		}
	}

	u64 writes_key = WRITES;

	u64* writes_list = bpf_map_lookup_elem(&relevant_state_info,&writes_key);

	
	if (writes_list){
		//bpf_printk("write_state[0] is %llu and write_state[1] is %llu and writes value is %llu \n", writes_list[0],writes_list[1],writes);

		for (int i=0;i<fault_count;i++){
			if (writes_list[i] == writes && writes_list[i] != 0){
				//bpf_printk("Sent to userspace from write with value %llu \n",writes_list[i]);

				struct event *e;

				/* reserve sample from BPF ringbuf */
				e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
				if (!e)
					return 0;

				e->type = WRITE_HOOK;
				e->writes = writes_now;
				bpf_ringbuf_submit(e, 0);
				writes+=1;
				return 0;
			}
			//bpf_printk("Skipped \n");
		}
		writes+=1;
		return 0;
		//Should track writes?
		//bpf_map_update_elem(&exec_map, &ts, &e, BPF_ANY);
	}

	return 0;
}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(__x64_sys_read)
{
		//safe so if other ebpf runs it does not change this value
	int reads_now = reads;

	int read_syscall = READ;

	int* inject = bpf_map_lookup_elem(&syscalls_to_fail,&read_syscall);

	if (inject){
		if (*inject){
			if (reads_blocked < 10){
				bpf_printk("Blocked read \n");
				reads_blocked+=1;
				bpf_override_return(ctx, -1);
			}
		}
	}

	u64 reads_key = READ;

	u64* reads_list = bpf_map_lookup_elem(&relevant_state_info,&reads_key);

	
	if (reads_list){
		//bpf_printk("write_state[0] is %llu and write_state[1] is %llu and writes value is %llu \n", writes_list[0],writes_list[1],writes);

		for (int i=0;i<fault_count;i++){
			if (reads_list[i] == writes && reads_list[i] != 0){
				//bpf_printk("Sent to userspace from write with value %llu \n",writes_list[i]);

				struct event *e;

				/* reserve sample from BPF ringbuf */
				e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
				if (!e)
					return 0;

				e->type = WRITE_HOOK;
				e->writes = reads_now;
				bpf_ringbuf_submit(e, 0);
				reads+=1;
				return 0;
			}
			//bpf_printk("Skipped \n");
		}
		reads+=1;
		return 0;
		//Should track writes?
		//bpf_map_update_elem(&exec_map, &ts, &e, BPF_ANY);
	}
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