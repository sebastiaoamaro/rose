#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs.h"
#include "aux.h"
#include "fs.bpf.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
	__type(key, struct info_key);
	__type(value, struct info_state);
	 __uint(pinning, LIBBPF_PIN_BY_NAME);
} relevant_state_info SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");

const volatile int fault_count = 0;

SEC("fentry/vfs_fstatat")
int BPF_PROG(vfs_fstatat, int dfd,char * filename)
{
	// pid_t pid;

	// pid = bpf_get_current_pid_tgid() >> 32;

	// struct info_key information = {
	// 	pid,
	// 	VFS_FSTATAT_SPECIFIC
	// };

	// struct info_state *current_state;

	// current_state = bpf_map_lookup_elem(&relevant_state_info,&information);

	// if (current_state){
	// 	struct file_info_simple *file_stat = bpf_map_lookup_elem(&files,&pid);
	// 	if(file_stat){
	// 		if(string_contains(file_stat,filename,sizeof(filename))){
	// 			//bpf_printk("%s %s\n",&file_stat->filename,filename);

    //             struct event *e;

	// 			/* reserve sample from BPF ringbuf */
	// 			e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	// 			if (!e)
	// 				return 0;
    //             bpf_probe_read(e->filename, sizeof(&file_stat->filename), &file_stat->filename);

	// 			e->type = VFS_FSTATAT_SPECIFIC;
	// 			bpf_ringbuf_submit(e, 0);

    //         }
	// 	}
	// }


    // int result = process_current_state(VFS_FSTATAT_COUNT,VFS_FSTATAT_HOOK,pid);

	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit_open(struct trace_event_raw_sys_exit *ctx){

    // long fd = ctx->ret;

    // __u64 pid_tgid = bpf_get_current_pid_tgid();
	// __u32 pid = pid_tgid >> 32;
	// __u32 tid = (__u32)pid_tgid;

    // //bpf_printk("%ld \n",fd);

    // FileFDKey fdkey = {};

    // if (fd > 0){
    //     //bpf_printk("%d \n",fd);

    //     struct file *file = get_file_from_fd(fd);

    //     if(!file){
    //         //bpf_printk("File not found \n");
    //         return 1;
    //     }

    //     struct path path = get_path_from_file(file);

    //     struct inode *inode = get_inode_from_path(&path);

    //     if (!inode) return 2;
    //     if (get_file_tag(&fdkey, inode)) return 2;

    //     EventPath event_path = {};
    //     event_path.etype = 0;
    //     event_path.n_ref = 0;
    //     event_path.index = 0;
    //     event_path.cpu = bpf_get_smp_processor_id();

    //     FileInfo fi = {};

    //     bpf_probe_read(&fi.file_type, sizeof(fi.file_type), &inode->i_mode);

    //     if (get_file_path(&path, &event_path, &fi) != 0) return 2;


    //     struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&pid);

    //     if(file_open){
    //         //bpf_printk("%s and %s and str_len is %d \n",&file_open->filename,&(fi.filename[fi.offset]),file_open->size);
    //         if(equal_to_true(file_open,&(fi.filename[fi.offset]),fi.offset)){
    //             struct event *e;

	// 			/* reserve sample from BPF ringbuf */
	// 			e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	// 			if (!e)
	// 				return 0;
    //             bpf_probe_read(e->filename, sizeof(fi.filename), &(fi.filename[fi.offset]));

	// 			e->type = FSYS;
	// 			bpf_ringbuf_submit(e, 0);

                
    //         }
    //     }

    //}

    return 0;

}
