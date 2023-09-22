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
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, struct file_info_simple);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");



SEC("tp/syscalls/sys_enter_openat")
int handle_open(struct trace_event_raw_sys_enter *ctx){

    return 0;

}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit_open(struct trace_event_raw_sys_exit *ctx){

    long fd = ctx->ret;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

    //bpf_printk("%ld \n",fd);

    FileFDKey fdkey = {};

    if (fd > 0){
        //bpf_printk("%d \n",fd);

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


        struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&pid);

        if(file_open){
            //bpf_printk("%s and %s and str_len is %d \n",&file_open->filename,&(fi.filename[fi.offset]),file_open->size);
            if(equal_to_true(file_open,&(fi.filename[fi.offset]),fi.offset)){
                struct event *e;

				/* reserve sample from BPF ringbuf */
				e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
				if (!e)
					return 0;
                bpf_probe_read(e->filename, sizeof(fi.filename), &(fi.filename[fi.offset]));

				e->type = FSYS;
				bpf_ringbuf_submit(e, 0);

                
            }
        }

    }

    return 0;

}

SEC("tp/syscalls/sys_enter_lseek")
int handle_enter(struct trace_event_raw_sys_enter *ctx){

    return 0;

}

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx){
    
    return 0;
}
