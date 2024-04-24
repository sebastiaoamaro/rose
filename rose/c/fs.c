#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "aux.h"
#include "fs.h"
#include "fs.skel.h"
#include <pthread.h>

struct fs_bpf* monitor_fs(int fault_count){
    
    struct fs_bpf *skel;

    int err;

    skel = fs_bpf__open();

    if (!skel){
        fprintf(stderr,"Failed to open and load BPF skeleton");
        return NULL;
    }

    //int err_flag = bpf_program__set_flags(skel->progs.vfs_fstatat,BPF_F_SLEEPABLE);
	//printf("Err is %d \n",err_flag);
    skel->rodata->fault_count = fault_count;
    /* Load & verify BPF programs */
	err = fs_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return NULL;
    }

	/* Attach tracepoints */
	err = fs_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return NULL;
	}

    return skel;
}