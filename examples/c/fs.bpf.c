#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs.h"
#include "aux.h"
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

static inline struct file* get_file_from_fd(int32_t fd)
{
    if (fd < 0) return NULL;

    struct task_struct *curr_task = (struct task_struct *) bpf_get_current_task();
    if (!curr_task) return NULL;

    struct files_struct *files = NULL;
    bpf_probe_read(&files, sizeof(files), &curr_task->files);
    if (!files) return NULL;

    struct fdtable *fdtable = NULL;
    bpf_probe_read(&fdtable, sizeof(fdtable), &files->fdt);
    if (!fdtable) return NULL;

    struct file **fileptr = NULL;
    bpf_probe_read(&fileptr, sizeof(fileptr), &fdtable->fd);
    if (!fileptr) return NULL;

    struct file *file = NULL;
    bpf_probe_read(&file, sizeof(file), &fileptr[fd]);

    return file;
}

static inline struct path get_path_from_file(struct file *file) {
    struct path path;
    bpf_probe_read(&path, sizeof(path), (const void*)&file->f_path);
    return path;
}

static inline struct inode* get_inode_from_path(struct path *path ) {
    struct inode *inode;
    struct dentry *dentry = path->dentry;
    if(!dentry) return NULL;
    bpf_probe_read(&inode, sizeof(inode), &dentry->d_inode);
    return inode;
}

static inline int get_file_tag(FileFDKey *file_tag, struct inode *inode) {
    struct super_block	*i_sb = NULL;
    bpf_probe_read(&i_sb, sizeof(struct i_sb*), &inode->i_sb);
    if (!i_sb) return -1;

    bpf_probe_read(&file_tag->ino, sizeof(file_tag->ino), &inode->i_ino);
    bpf_probe_read(&file_tag->dev, sizeof(file_tag->dev), &i_sb->s_dev);

    return 0;
}

static inline struct dentry* get_dentry_from_path(struct path *path ) {
    return path->dentry;
}

static inline struct vfsmount* get_mnt_from_path(struct path *path ) {
    return path->mnt;
}

static inline struct mount* get_real_mount(struct vfsmount *vfs_mnt) {
    return container_of(vfs_mnt, struct mount, mnt);
}

static inline struct mount* get_mount_parent(struct mount *mnt) {
    struct mount *mount_p;
    bpf_probe_read(&mount_p, sizeof(struct mount *), &mnt->mnt_parent);
    return mount_p;
}

static inline int get_file_path(struct path *path, struct event_path_t *event_path, FileInfo *fi) {
    u32 i, len, offset, last_position;
    char slashchar = '/', nulchar = '\0';
    struct dentry *dentry, *parent, *mnt_root;
    struct vfsmount *vfs_mnt;
    struct mount *real_mount, *mount_parent;
    struct qstr d_name;
    int flag = 0;
    dentry = get_dentry_from_path(path);
    if (!dentry) return 1;
    vfs_mnt = get_mnt_from_path(path);
    if (!vfs_mnt) return 1;
    real_mount = get_real_mount(vfs_mnt);
    if (!real_mount) return 1;
    mount_parent = get_mount_parent(real_mount);
    if (!mount_parent) return 1;
    offset = last_position = MAX_FILE_OFFSET;
#pragma unroll
    for (i = 0; i < MAX_JUMPS; i++) {
        // get parent dentry
        bpf_probe_read_kernel((void *) &parent, sizeof(parent), (void*)&(dentry->d_parent));
        if (!parent) break;
        // get mount root dentry
        bpf_probe_read_kernel((void *) &mnt_root, sizeof(mnt_root), (void*)&(vfs_mnt->mnt_root));
        if (!mnt_root) break;
        // stop if dentry equals parent or mount root
        if (dentry == mnt_root || dentry == parent)  {
            // find final root through the mount point
            if (dentry == mnt_root && real_mount != mount_parent) {
                bpf_probe_read(&dentry, sizeof(dentry), &real_mount->mnt_mountpoint);
                bpf_probe_read(&real_mount, sizeof(real_mount), &real_mount->mnt_parent);
                bpf_probe_read(&mount_parent, sizeof(mount_parent), &real_mount->mnt_parent);
                vfs_mnt = &real_mount->mnt;
                continue;
            }
            // reached end -> stop
            flag=1;
            if (i>0) offset++;
        }
        // get file name length
        bpf_probe_read_kernel(&d_name, sizeof(d_name), (const void*)&(dentry->d_name));
        len = d_name.len + 1;
        if (len >= SUB_STR_MAX) len = SUB_STR_MAX-1;
        len = len & (SUB_STR_MAX-1);
        // calculate new position to write
        offset = (offset - len);
        if (offset > last_position) break;
        // copy file name into buffer
        len = (len-1) &  (MAX_FILE_OFFSET - 1);
        int err = bpf_probe_read_kernel(&(fi->filename[offset & (MAX_FILE_OFFSET-1)]), len, (void *) d_name.name);
        if (err < 0) break;
        if (flag) {
            last_position = offset;
            break;
        }
        // Add a slash character
        last_position--;
        bpf_probe_read_kernel(&(fi->filename[last_position & (FILENAME_MAX-1)]), 1, &slashchar);
        last_position = offset;
        // get parent dentry name
        dentry = parent;
    }
    fi->offset = last_position;
    if (last_position == MAX_FILE_OFFSET) fi->size = MAX_FILE_OFFSET - last_position;
    else fi->size = MAX_FILE_OFFSET - last_position - 1;
    return 0;
}

static inline bool equal_to_true(struct file_info_simple *file_info,char *str2,uint32_t size) {
    char comparand[FILENAME_MAX];
    char comparand2[FILENAME_MAX];
    bpf_probe_read(&comparand, sizeof(comparand), file_info->filename);
    bpf_probe_read(&comparand2, sizeof(comparand2), str2);

    int str_len = file_info->size;

    int count = 0;
    #pragma unroll
    for (int i = 0; i < FILENAME_MAX; ++i){
        if (comparand[count] == comparand2[i] ){
            count++;
            continue;
        }
        if(str_len == count){
            return true; 
        }
        else{
            count = 0;
        }
    }

    return false;
}


SEC("tp/syscalls/sys_enter_openat")
int handle_open(struct trace_event_raw_sys_enter *ctx){

    return 0;

}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit_open(struct trace_event_raw_sys_exit *ctx){

    long fd = ctx->ret;

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


        int files_open = ANY_PID;

        struct file_info_simple *file_open = bpf_map_lookup_elem(&files,&files_open);

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
