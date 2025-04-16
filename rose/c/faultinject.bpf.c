// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>
#include "state_processor.bpf.h"
#include "faultinject.h"
#include "aux.h"
#include "fs.bpf.h"
#include "fs.h"
#include <bpf/usdt.bpf.h>
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
	__uint(max_entries, 16384);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nodes_pid_translator SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, int);
	__type(value,int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pids SEC(".maps");

const volatile int fault_count = 0;

const volatile int time_only = 0;


/* Declare the external kfunc */
extern int bpf_strstr(const char* str,const char* str2, int str_len) __ksym;
extern int bpf_compare_str(const char* str,const char* str2, int str_len) __ksym;

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


	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	int origin_pid = get_origin_pid(pid, &nodes_pid_translator);

	FileFDKey fdkey = {};

	int process_fd = 1;

	//struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	// if(fdrelevant){
	// 	for (int i=0;i<fdrelevant->size;i++){
	// 		if(i>MAX_RELEVANT_FILES)
	// 			break;
	// 		__u64 relevant_fd = fdrelevant->fds[i];
	// 		if(relevant_fd == fd){
	// 			process_fd = 0;
	// 			process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	// 			inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);
	// 			break;
	// 		}
	// 	}
	// }else{
	// 	process_fd = 0;
	// }

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
			origin_pid,
			sys_info.file_specific_code
		};
		struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);
		//bpf_printk("File is %s \n",&(fi.filename[fi.offset]));
		if(file_open){
			if (fi.size == 0){
				return 0;
			}
			//bpf_printk("Comparing %s and %s \n with offset %d",&(fi.filename[fi.offset]),file_open->filename,fi.size);
			if(string_contains(file_open->filename,&(fi.filename[fi.offset]),fi.size)){

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
				process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
					&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
				inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

			}else{
				return 0;
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

	int origin_pid = get_origin_pid(pid, &nodes_pid_translator);


	FileFDKey fdkey = {};

	int process_fd = 1;

	// struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	// if(fdrelevant){
	// 	for (int i=0;i<fdrelevant->size;i++){
	// 		if(i>MAX_RELEVANT_FILES)
	// 			break;
	// 		__u64 relevant_fd = fdrelevant->fds[i];
	// 		if(relevant_fd == fd){
	// 			process_fd = 0;
	// 			process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
	// 				&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	// 			inject_override(pid,sys_info.file_specific_code,(struct pt_regs *) ctx,0,&faults_specification);
	// 			break;
	// 		}
	// 	}
	// }else{
	// 	process_fd = 0;
	// }

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

		if (get_file_path(&path, &event_path, &fi) != 0){
		  bpf_printk("Get file path failed \n");
		  return 2;
		}

		struct info_key info_key = {
			origin_pid,
			sys_info.file_specific_code
		};
		struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);
		if(file_open){
			if (fi.size == 0){
				return 0;
			}
			//bpf_printk("PID:%d, READ_FILE: %s, FILE_COND: %s \n",pid,&(fi.filename[fi.offset]),file_open->filename);

			if(string_contains(file_open->filename,&(fi.filename[fi.offset]),file_open->size)){
				struct relevant_fds *fds = bpf_map_lookup_elem(&relevant_fd,&pid);

				//bpf_printk("In read found %s and %s \n",&(fi.filename[fi.offset]),file_open->filename);
				if(fds){
					u64 position = fds->size;
					if(position < MAX_RELEVANT_FILES){
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

	int origin_pid = get_origin_pid(pid, &nodes_pid_translator);

	int fd = PT_REGS_PARM1_CORE(regs);

	//Remove relevant fd from map if it was closed

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&pid);

	if(fdrelevant){
		for (int i=0;i<fdrelevant->size;i++){
			if(i>MAX_RELEVANT_FILES)
				break;
			u64 relevant_fd = fdrelevant->fds[i];
			if(relevant_fd == fd){
			    //bpf_printk("Closing fd %d\n",fd);
				fdrelevant->fds[i] = 0;
				break;
			}
		}
	}
		struct sys_info sys_info = {
		fd,
		CLOSE_STATE,
		0,
		CLOSE_FAULT,
		0,
		fault_count,
		time_only
	};

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

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

	int origin_pid = get_origin_pid(pid, &nodes_pid_translator);

	struct sys_info sys_info = {
		0,
		OPENNAT_COUNT,
		OPENAT_SPECIFIC,
		OPENAT_FAULT,
		OPENAT_FILE,
		fault_count,
		time_only
	};

	char *path = (char*) PT_REGS_PARM2_CORE(regs);
	struct info_key info_key = {
		origin_pid,
		sys_info.file_specific_code
	};
	struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);

	if(file_open){
    	int string_equal = 0;
    	for (int i = 0; i < 4; i++){
    		const char str1[64];
      		bpf_probe_read(&str1, sizeof(str1),path+i*64);
            //-1 Because of \0
    		int result = bpf_strstr(file_open->filename,str1,file_open->size-1);
    		if (result){
    			string_equal = result;
    			break;
    		}
    	}
    	if (!string_equal){
    		//bpf_printk("Could not find string in openat \n");
    		return 0;
    	}
        bpf_printk("ORIGIN_PID:%d,PID:%d,FILENAME:%s, PATH:%s, SIZE: %d \n",origin_pid,pid,file_open->filename,path,file_open->size);
		process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
			&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
		inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);
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
            if(string_contains(file_info->filename,&(fi.filename[fi.offset]),fi.offset)){
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

	struct sys_info sys_info = {
		0,
		NEWFSTATAT_STATE,
		NEWFSTATAT_FILE_STATE,
		NEWFSTATAT_FAULT,
		NEWFSTATAT_FILE_FAULT,
		fault_count,
		time_only
	};

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	int origin_pid = get_origin_pid(pid, &nodes_pid_translator);


	char *path =  (char*) PT_REGS_PARM2_CORE(regs);

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&origin_pid);

	struct info_key info_key = {
		pid,
		sys_info.file_specific_code
	};
	struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&info_key);
	if(file_open){

			//bpf_printk("In open comparing %s and %s \n",path,file_open->filename);

			int string_equal = 0;
			for (int i = 0; i < 4; i++){
				const char str1[64];
				bpf_probe_read(&str1, sizeof(str1),path+i*64);
				int result = bpf_strstr(file_open->filename,str1,file_open->size);
				if (result){
					//bpf_printk("Found matching string %s and %s \n",file_open->filename,path);
					string_equal = result;
					break;
				}
			}

			if (!string_equal){
				//bpf_printk("Could not find string in openat \n");
				return 0;
			}
			process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,
				&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
			inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);


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

	int fd = PT_REGS_PARM1_CORE(regs);

	struct sys_info sys_info = {
		fd,
		FSYNC_STATE,
		FSYNCFILE_STATE,
		FSYNC,
		FSYNC_FILE,
		fault_count,
		time_only
	};

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

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

	int origin_pid = get_origin_pid(pid, &nodes_pid_translator);


	FileFDKey fdkey = {};

	int process_fd = 1;

	struct relevant_fds *fdrelevant = bpf_map_lookup_elem(&relevant_fd,&origin_pid);

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

			if(file_open->size == 0){
				return 0;
			}

			bpf_printk("In fdatasync comparing %s and %s \n",&(fi.filename[fi.offset]),file_open->filename);
			if(string_contains(file_open,&(fi.filename[fi.offset]),fi.size)){
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
				process_current_state(sys_info.file_specific_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
				inject_override(pid,sys_info.file_specific_fault_code,(struct pt_regs *) ctx,0,&faults_specification);

			}
		}
	}

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);
}

SEC("kretsyscall/fdatasync")
int BPF_KPROBE(__x64_sys_fdatasync_ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;


	//int result = process_current_state(NEWFSTATAT_COUNT,NEWFSTATAT_HOOK,tid);
	inject_override(pid,FDATASYNC_RET_FAULT,(struct pt_regs *) ctx,0,&faults_specification);


	return 0;
}

SEC("ksyscall/pwrite64")
int BPF_KPROBE(__x64_sys_pwrite64,struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	struct sys_info sys_info = {
		0,
		PWRITE64_STATE,
		0,
		PWRITE64_FAULT,
		0,
		fault_count,
		time_only
	};


	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);


	return 0;
}

SEC("ksyscall/accept")
int BPF_KPROBE(__x64_sys_accept,struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	struct sys_info sys_info = {
		0,
		ACCEPT_STATE,
		0,
		ACCEPT_FAULT,
		0,
		fault_count,
		time_only
	};


	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);


	return 0;
}

SEC("ksyscall/futex")
int BPF_KPROBE(__x64_sys_futex,struct pt_regs *regs)
{

	int op = (int) PT_REGS_PARM2_CORE(regs);

	if (op != 0 & 128){
		//bpf_printk("Not a wait op \n");
		return 0;
	}
	//bpf_printk("Op value is %d \n",op);

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	struct sys_info sys_info = {
		0,
		FUTEX_STATE,
		0,
		FUTEX_FAULT,
		0,
		fault_count,
		time_only
	};

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);


	return 0;
}

SEC("ksyscall/connect")
int BPF_KPROBE(__x64_sys_connect,struct pt_regs *regs)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	struct sys_info sys_info = {
		0,
		CONNECT_STATE,
		0,
		CONNECT_FAULT,
		0,
		fault_count,
		time_only
	};

	process_current_state(sys_info.general_syscall_code,pid,sys_info.fault_count,sys_info.time_only,&relevant_state_info,&faults_specification,&faults,&rb,&auxiliary_info,&nodes_status,&nodes_pid_translator);
	inject_override(pid,sys_info.general_fault_code,(struct pt_regs *) ctx,0,&faults_specification);


	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent;
    int ppid = 0;

    if (task) {
        parent = task->real_parent;
        if (parent) {
            ppid = parent->pid;
        }
    }
    int original_pid = ppid;
   	int *parent_pid_pointer = bpf_map_lookup_elem(&pids,&ppid);

	if (!parent_pid_pointer) {
	   return 0;
	}

	int parent_pid = *parent_pid_pointer;

    int count = 0;

    //Loop through existing pids to know the origin node
    while (parent_pid && count < 20) {
        if (parent_pid == 1){
            int *start_pid = bpf_map_lookup_elem(&nodes_pid_translator,&original_pid);

            if (start_pid){
                bpf_map_update_elem(&nodes_pid_translator, &pid, &start_pid, BPF_ANY);
            }
            else{
                //Temporary fix for all my tests that used exec -a
                if (original_pid != 0){
                    bpf_map_update_elem(&nodes_pid_translator, &pid, &original_pid, BPF_ANY);
                }
            }
            break;

        }else{
            bpf_map_update_elem(&pids, &pid, &parent_pid,BPF_ANY);
        }
        original_pid = parent_pid;
        parent_pid_pointer = bpf_map_lookup_elem(&pids,&parent_pid);
        if(parent_pid_pointer){
            parent_pid = *parent_pid_pointer;
        }
        count++;
    }
	return 0;
}

// SEC("usdt")
// int entry_probe(struct pt_regs *ctx){

//     char name[64] = {0};

//     void *method_name = (void *)PT_REGS_PARM3(ctx);

//     if (!method_name){
//         bpf_printk("No method name provided\n");
//         return 0;
//     }
//     //bpf_printk("Name is %s \n",(char *)method_name);

//     int len = bpf_probe_read_user_str(&name, sizeof(name), method_name);

//     if (len < 0){
//         //bpf_printk("Failed to read method name, err is %d", len);
//         return 0;
//     }

//     //bpf_printk("Entering method: %s\n", name);
// 	return 0;
// }
