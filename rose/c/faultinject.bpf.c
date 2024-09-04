// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "state_processor.bpf.h"
#include "faultinject.h"
#include "aux.h"
#include "fs.bpf.h"
#include "fs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct fault_key);
	__type(value, struct fault_description);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faults_specification SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct info_key);
	__type(value, struct info_state);
	 __uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_state_info SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, struct info_key);
	__type(value, struct file_info_simple);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,struct relevant_fds);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_FAULTS);
	__type(key, int);
	__type(value, struct simplified_fault);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} faults SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} active_write_fd SEC(".maps");

//Struct to hold time
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} time SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} auxiliary_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nodes_status SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAP_SIZE);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nodes_pid_translator SEC(".maps");


const volatile int fault_count = 0;

const volatile int time_only = 0;

//static int process_fd_syscall(struct pt_regs *ctx,struct sys_info sys_info,struct bpf_map *relevant_state_info,struct bpf_map *faults_specification,struct bpf_map *faults,struct bpf_map *rb);

// static void call_state_processor(struct sys_info sys_info,int pid){
// 	process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes);
// }

SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(__x64_sys_write,struct pt_regs *regs)
{
	int fd = PT_REGS_PARM1_CORE(regs);

	struct sys_info sys_info = {
		fd,
		WRITES,
		WRITE_FILE_STATE,
		WRITE,
		WRITE_FILE,
		fault_count,
		time_only
	};

	//process_fd_syscall(ctx,&sys_info,&relevant_state_info,&faults_specification,&faults,&rb,&files,&relevant_fd);

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	FileFDKey fdkey = {};

	int process_fd = 1;

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	if(fdrelevant){
		for (int i=0;i<fdrelevant->size;i++){
			if(i>MAX_RELEVANT_FILES)
				break;
			__u64 relevant_fd = fdrelevant->fds[i];
			if(relevant_fd == fd){
				bpf_printk("Found relevant fd \n");
				process_fd = 0;
				process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
				inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);
				break;
			}
		}
	}else{
		process_fd = 0;
	}

	if (fd > 0 && process_fd){
		struct file *file = get_file_from_fd(fd);

		if(!file){
			//bpf_printk("File not found \n");
			return 2;
		}

		struct path path = get_path_from_file(file);

		struct inode *inode = get_inode_from_path(&path);

		if (!inode) return 2;
		if (get_file_tag(&fdkey, inode)) return 2;

		EventPath event_path = {};
		event_path.etype = 0;
		event_path.n_ref = 0;
		event_path.index = 0;
		event_path.cpu = bpf_get_smp_processor_id();

		FileInfo fi = {};

		bpf_probe_read(&fi.file_type, sizeof(fi.file_type), &inode->i_mode);

		if (get_file_path(&path, &event_path, &fi) != 0) return 2;

		struct info_key info_key = {
			pid,
			sys_info.file_specific_code
		};
		struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);
		bpf_printk("File is %s \n",&(fi.filename[fi.offset]));
		if(file_open){
			//bpf_printk("Comparing %s and %s \n",&(fi.filename[fi.offset]),file_open->filename);
			if(string_contains(file_open,&(fi.filename[fi.offset]),fi.offset)){
				bpf_printk("Found %s and %s \n",&(fi.filename[fi.offset]),file_open->filename);
				struct relevant_fds *fds = bpf_map_lookup_elem(&relevant_fd,&pid);
				if(fds){
					u64 position = fds->size;
					if(position < MAX_RELEVANT_FILES){
						bpf_printk("Adding fd %d to pos %d",fd,fds->size);
						fds->fds[position] = fd;
						fds->size = fds->size + 1;
					}
				}else{
					bpf_printk("This should not happen, main should init the structures \n");
				}
				process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
					&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
				inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

			}
		}
	}

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,
		&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

	return 0;
}

SEC("kretprobe/__x64_sys_write")
int BPF_KRETPROBE(__x64_sys_ret_write,struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	inject_override(pid,WRITE_RET,(struct pt_regs *) ctx,0,&faults_specification);

	return 0;

}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(__x64_sys_read,struct pt_regs *regs)
{
	int fd = PT_REGS_PARM1_CORE(regs);

	struct sys_info sys_info = {
		fd,
		READS,
		READ_FILE,
		READ,
		READ_FILE_STATE,
		fault_count,
		time_only
	};

		__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	FileFDKey fdkey = {};

	int process_fd = 1;

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	if(fdrelevant){
		for (int i=0;i<fdrelevant->size;i++){
			if(i>MAX_RELEVANT_FILES)
				break;
			__u64 relevant_fd = fdrelevant->fds[i];
			if(relevant_fd == fd){
				process_fd = 0;
				process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
					&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
				inject_override(pid,sys_info.file_specific_code,(struct pt_regs *) ctx,0,&faults_specification);
				break;
			}
		}
	}else{
		process_fd = 0;
	}

	if (fd > 0 && process_fd){
		struct file *file = get_file_from_fd(fd);

		if(!file){
			//bpf_printk("File not found \n");
			return 2;
		}

		struct path path = get_path_from_file(file);

		struct inode *inode = get_inode_from_path(&path);

		if (!inode) return 2;
		if (get_file_tag(&fdkey, inode)) return 2;

		EventPath event_path = {};
		event_path.etype = 0;
		event_path.n_ref = 0;
		event_path.index = 0;
		event_path.cpu = bpf_get_smp_processor_id();

		FileInfo fi = {};

		bpf_probe_read(&fi.file_type, sizeof(fi.file_type), &inode->i_mode);

		if (get_file_path(&path, &event_path, &fi) != 0) return 2;

		struct info_key info_key = {
			pid,
			sys_info.file_specific_code
		};
		struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);
		if(file_open){
			//bpf_printk("Comparing %s and %s \n",&(fi.filename[fi.offset]),file_open->filename);
			if(string_contains(file_open,&(fi.filename[fi.offset]),fi.offset)){
				struct relevant_fds *fds = bpf_map_lookup_elem(&relevant_fd,&pid);
				if(fds){
					u64 position = fds->size;
					if(position < MAX_RELEVANT_FILES){
						bpf_printk("Adding fd %d to pos %d",fd,fds->size);
						fds->fds[position] = fd;
						fds->size = fds->size + 1;
					}
				}else{
					bpf_printk("This should not happen, main should init the structures \n");
				}
				process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
					&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
				inject_override(pid,sys_info.file_specific_code,(struct pt_regs *) ctx,0,&faults_specification);

			}
		}
	}

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,
		&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

	//process_fd_syscall(ctx,&sys_info,&relevant_state_info,&faults_specification,&faults,&rb,&files,&relevant_fd);
	//call_state_processor_fd_syscall(ctx,&sys_info);
	return 0;
}


SEC("kprobe/__x64_sys_close")
int BPF_KPROBE(__x64_sys_close,struct pt_regs *regs)
{
	//safe so if other ebpf runs it does not change this value

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	int fd = PT_REGS_PARM1_CORE(regs);

	//Remove relevant fd from map if it was closed

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	if(fdrelevant){
		for (int i=0;i<fdrelevant->size;i++){
			if(i>MAX_RELEVANT_FILES)
				break;
			u64 relevant_fd = fdrelevant->fds[i];
			if(relevant_fd == fd){

				fdrelevant->fds[i] = 0;
				break;
			}
		}
	}
	//TODO IMPLEMENT FOR CLOSE

	// struct sys_info sys_info = {
	// 	fd,
	// 	READS,
	// 	READ_FILE,
	// 	READ,
	// 	fault_count,
	// 	time_only
	// };

	// process_fd_syscall(ctx,sys_info,&relevant_state_info,&faults_specification,&faults,&rb,&files,&relevant_fd);
	return 0;
}

SEC("ksyscall/open")
int BPF_KPROBE(__x64_sys_open)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	int result = process_current_state(OPENS,pid,fault_count,time_only,
		&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);

	inject_override(pid,OPEN,(struct pt_regs *) ctx,0,&faults_specification);


	return 0;
}

SEC("ksyscall/openat")
int BPF_KPROBE(__x64_sys_openat,struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	struct sys_info sys_info = {
			0,
			OPENNAT_COUNT,
			OPENAT_SPECIFIC,
			OPENAT,
			OPENAT_FILE,
			fault_count,
			time_only
		};

	char *path = PT_REGS_PARM2_CORE(regs);

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	struct info_key info_key = {
		pid,
		sys_info.file_specific_code
	};
	struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);
	if(file_open){
		if(string_contains(file_open->filename,path,file_open->size)){
			//bpf_printk("path is %s \n",path);
			//bpf_printk("file_open is %s \n",file_open->filename);
			process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
				&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
			inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

		}
	}

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,
		&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

	return 0;
}

SEC("kretsyscall/openat")
int BPF_KRETPROBE(__x64_sys_openat_ret)
{
	long fd = PT_REGS_RC((struct pt_regs *) ctx);

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	FileFDKey fdkey = {};
	int process_fd = 0;

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	if(fdrelevant){
		if(fdrelevant->size){
			for (int i=0;i<fdrelevant->size;i++){
				if(i>MAX_RELEVANT_FILES)
					break;
				u64 relevant_fd = fdrelevant->fds[i];
				if (relevant_fd == fd){
					//bpf_printk("This fd is important but we already processed it \n");
					inject_override(pid,OPENAT_RET,(struct pt_regs *) ctx,0,&faults_specification);
				}
			}
			process_fd = 1;

		}
		else{
			process_fd = 1;
		}
	}

	if (fd > 0 && process_fd){

        struct file *file = get_file_from_fd(fd);

        if(!file){
            //bpf_printk("File not found \n");
            return 1;
        }

        struct path path = get_path_from_file(file);

        struct inode *inode = get_inode_from_path(&path);

        if (!inode) return 2;
        if (get_file_tag(&fdkey, inode)) return 2;

        EventPath event_path = {};
        event_path.etype = 0;
        event_path.n_ref = 0;
        event_path.index = 0;
        event_path.cpu = bpf_get_smp_processor_id();

        FileInfo fi = {};

        bpf_probe_read(&fi.file_type, sizeof(fi.file_type), &inode->i_mode);

        if (get_file_path(&path, &event_path, &fi) != 0) return 2;

		struct info_key info_key = {
			pid,
			OPENAT_SPECIFIC
		};

        struct file_info_simple *file_info = bpf_map_lookup_elem(&files,&pid);

        if(file_info){
            if(string_contains(file_info,&(fi.filename[fi.offset]),fi.offset)){
				//bpf_printk("%s and %s and fd is %d \n",&file_info->filename,&(fi.filename[fi.offset]),fd);
				struct relevant_fds *fds = bpf_map_lookup_elem(&relevant_fd,&pid);
				if(fds){
					u64 position = fds->size;
					if(position < MAX_RELEVANT_FILES){
						fds->fds[position] = fd;
						fds->size = fds->size + 1;
					}
				}else{
					bpf_printk("This should not happen, main should init the structures \n");
				}

				inject_override(pid,OPENAT_RET,(struct pt_regs *) ctx,0,&faults_specification);

            }
        }
    }

	//int result = process_current_state(OPENAT_COUNT,OPENNAT_HOOK,pid);
	inject_override(pid,OPENAT_RET,(struct pt_regs *) ctx,0,&faults_specification);


	//TODO IMPLEMENT FOR RETS NO STATE_INFO INCREMENTATION
	// struct sys_info sys_info = {
	// 	fd,
	// 	OPENNAT_COUNT,
	// 	READ_FILE,
	// 	OPENAT_RET,
	// 	fault_count,
	// 	time_only
	// };

	// process_fd_syscall(ctx,sys_info,&relevant_state_info,&faults_specification,&faults,&rb,&files,&relevant_fd);

	return 0;

}

SEC("kprobe/__x64_sys_mkdir")
int BPF_KPROBE(__x64_sys_mkdir)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	int result = process_current_state(DIRCREATED,pid,fault_count,time_only,
		&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);

	inject_override(pid,MKDIR,(struct pt_regs *) ctx,0,&faults_specification);

	return 0;
}

SEC("ksyscall/newfstatat")
int BPF_KPROBE(__x64_sys_newfstatat,struct pt_regs *regs)

{
	// __u64 pid_tgid = bpf_get_current_pid_tgid();
	// __u32 pid = pid_tgid >> 32;
	// __u32 tid = (__u32)pid_tgid;

	// int syscall_nr = process_current_state(NEWFSTATAT_COUNT,pid,fault_count,time_only,&relevant_state_info,&faults_specification,&faults,&rb);


	// char *path = PT_REGS_PARM2_CORE(regs);

	// struct info_key information = {
	// 	pid,
	// 	NEW_FSTATAT_SPECIFIC
	// };

	// struct info_state *current_state;

	// current_state = bpf_map_lookup_elem(&relevant_state_info,&information);

	// struct info_key info_key = {
	// 	pid,
	// 	NEW_FSTATAT_SPECIFIC
	// };

	// if (current_state){
	// 	struct file_info_simple *file_info = bpf_map_lookup_elem(&files,&info_key);
	// 	if(file_info){
	// 		if(string_contains(file_info,path,sizeof(path))){
	// 			//bpf_printk("%s %s are similar and syscall_nr is %d\n",&file_info->filename,path,syscall_nr);
	// 			process_current_state(NEW_FSTATAT_SPECIFIC,pid,fault_count,time_only,&relevant_state_info,&faults_specification,&faults,&rb);
    //         }
	// 	}
	// }
	// inject_override(pid,NEWFSTATAT,(struct pt_regs *) ctx,syscall_nr,&faults_specification);

	// struct sys_info sys_info = {
	// 	fd,
	// 	NEWFSTATAT_COUNT,
	// 	NEW_FSTATAT_SPECIFIC,
	// 	NEWFSTATAT,
	// 	fault_count,
	// 	time_only
	// };

	// process_fd_syscall(ctx,&sys_info,&relevant_state_info,&faults_specification,&faults,&rb,&files,&relevant_fd);

	struct sys_info sys_info = {
		0,
		NEWFSTATAT_COUNT,
		NEW_FSTATAT_SPECIFIC,
		NEWFSTATAT,
		NEWFSTATAT_FILE,
		fault_count,
		time_only
	};

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	char *path = PT_REGS_PARM2_CORE(regs);

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	struct info_key info_key = {
		pid,
		sys_info.file_specific_code
	};
	struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);
	if(file_open){
		if(string_contains(file_open->filename,path,file_open->size)){
			process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
				&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
			inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

		}
	}

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,
		&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

	return 0;
}

SEC("kretsyscall/newfstatat")
int BPF_KRETPROBE(__x64_sys_newfstatat_ret)

{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	//int result = process_current_state(NEWFSTATAT_COUNT,NEWFSTATAT_HOOK,tid);
	inject_override(pid,NEWFSTATAT_RET,(struct pt_regs *) ctx,0,&faults_specification);


	return 0;
}

SEC("ksyscall/clone")
int BPF_KSYSCALL(clone,int flags)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

    int THREAD_FLAG = 0x10000;


	if (!(flags & THREAD_FLAG)){
		return 0;
	}

	int result = process_current_state(THREADS_CREATED,pid,fault_count,time_only,
		&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,CLONE,(struct pt_regs *) ctx,0,&faults_specification);


	return 0;
}

SEC("ksyscall/clone3")
int BPF_KSYSCALL(clone3,struct clone_args *cl_args)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

    int THREAD_FLAG = 0x00010000;

	__u64 clone_flags;

	struct clone_args clone_args_new;

	bpf_probe_read_user(&clone_args_new, sizeof(clone_args_new), cl_args);

	if (!(clone_args_new.flags & THREAD_FLAG)){
		return 0;
	}


	int result = process_current_state(THREADS_CREATED,pid,fault_count,time_only,
		&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);

	inject_override(pid,CLONE,(struct pt_regs *) ctx,0,&faults_specification);

	return 0;
}

SEC("ksyscall/fsync")
int BPF_KPROBE(__x64_sys_fsync,struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	//bpf_printk("Detected fsync PID is %d \n",pid);
}

SEC("ksyscall/fdatasync")
int BPF_KPROBE(__x64_sys_fdatasync,struct pt_regs *regs)
{
	int fd = PT_REGS_PARM1_CORE(regs);

	struct sys_info sys_info = {
		fd,
		FDATASYNC_STATE,
		FDATASYNCFILE_STATE,
		FDATASYNC_FAULT,
		FDATASYNCFILE_FAULT,
		fault_count,
		time_only
	};

	//process_fd_syscall(ctx,&sys_info,&relevant_state_info,&faults_specification,&faults,&rb,&files,&relevant_fd);

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	FileFDKey fdkey = {};

	int process_fd = 1;

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	if(fdrelevant){
		for (int i=0;i<fdrelevant->size;i++){
			if(i>MAX_RELEVANT_FILES)
				break;
			__u64 relevant_fd = fdrelevant->fds[i];
			if(relevant_fd == fd){
				process_fd = 0;
				process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
					&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
				inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);
				break;
			}
		}
	}else{
		process_fd = 0;
	}

	if (fd > 0 && process_fd){
		struct file *file = get_file_from_fd(fd);

		if(!file){
			//bpf_printk("File not found \n");
			return 2;
		}

		struct path path = get_path_from_file(file);

		struct inode *inode = get_inode_from_path(&path);

		if (!inode) return 2;
		if (get_file_tag(&fdkey, inode)) return 2;

		EventPath event_path = {};
		event_path.etype = 0;
		event_path.n_ref = 0;
		event_path.index = 0;
		event_path.cpu = bpf_get_smp_processor_id();

		FileInfo fi = {};

		bpf_probe_read(&fi.file_type, sizeof(fi.file_type), &inode->i_mode);

		if (get_file_path(&path, &event_path, &fi) != 0) return 2;

		struct info_key info_key = {
			pid,
			sys_info.file_specific_code
		};
		struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);
		if(file_open){
			bpf_printk("Comparing %s and %s \n",&(fi.filename[fi.offset]),file_open->filename);
			if(string_contains(file_open,&(fi.filename[fi.offset]),fi.offset)){
				struct relevant_fds *fds = bpf_map_lookup_elem(&relevant_fd,&pid);
				if(fds){
					u64 position = fds->size;
					if(position < MAX_RELEVANT_FILES){
						bpf_printk("Adding fd %d to pos %d",fd,fds->size);
						fds->fds[position] = fd;
						fds->size = fds->size + 1;
					}
				}else{
					bpf_printk("This should not happen, main should init the structures \n");
				}
				process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
				inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

			}
		}
	}

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);
}
