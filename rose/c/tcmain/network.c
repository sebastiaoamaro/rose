// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "tc.skel.h"
#include "aux.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int()
{
	exiting = 1;
}

static struct bpf_tc_hook *tc_hook_handle;

struct bpf_tc_hook* get_tc_hook(int position){
	return &tc_hook_handle[position];
}

static struct bpf_tc_opts *tc_opts_handle;

struct bpf_tc_opts* get_tc_opts(int position){
	return &tc_opts_handle[position];
}

void init_tc(int count){
	tc_hook_handle = (struct bpf_tc_hook*)malloc(count*sizeof(struct bpf_tc_hook));
	tc_opts_handle = (struct bpf_tc_opts*)malloc(count*sizeof(struct bpf_tc_opts));

}
int main(int,char **argv)
{
    int index = atoi(argv[1]);
	int pos = atoi(argv[2]);
	int handle = atoi(argv[3]);
	int faults = atoi(argv[4]);
	int direction = atoi(argv[5]);

	printf("Index is %d,handle is %d, fault_count is %d, direction is %d \n",index,handle,faults,direction);
	// Docker changed netdevice number to be always 2, will depend on version
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
		.ifindex = index, .attach_point = direction);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
		.handle = handle, .priority = 1);
	bool hook_created = false;
	struct tc_bpf *skel;
	int err;

	//libbpf_set_print(libbpf_print_fn);

	skel = tc_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 0;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */

	//Pos is the original index-1, since docker is always 2 we need an extra variable
	skel->rodata->if_index = pos;

	skel->rodata->fault_count = faults;

	skel->rodata->network_direction = direction;

	err = tc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 0;
	}

	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		return 0;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.monitor);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		return 0;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
	}


	while (!exiting) {
		sleep(1);
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	tc_bpf__destroy(skel);

	return -err;

}

char** get_device_names(int device_count){
	char **device_names = malloc(32*sizeof(char));
	int count_devices;

	count_devices = get_interface_names(device_names,device_count);

	for (int i=0;i<count_devices;i++){
		printf("Device name is %s \n",device_names[i]);
	}

	return device_names;
}
