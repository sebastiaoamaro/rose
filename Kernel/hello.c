/* 
 * hello-5.c - Demonstrates command line argument passing to a module. 
 */ 
#include <linux/init.h> 
#include <linux/kernel.h> /* for ARRAY_SIZE() */ 
#include <linux/module.h> 
#include <linux/moduleparam.h> 
#include <linux/printk.h> 
#include <linux/stat.h> 
#include <linux/bpf.h>
#include <linux/file.h>
#include <linux/eventpoll.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#define IS_FD_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_CGROUP_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
#define IS_FD_PROG_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PROG_ARRAY)
#define IS_FD_HASH(map) ((map)->map_type == BPF_MAP_TYPE_HASH_OF_MAPS)
#define IS_FD_MAP(map) (IS_FD_ARRAY(map) || IS_FD_PROG_ARRAY(map) || \
			IS_FD_HASH(map))

MODULE_LICENSE("GPL"); 
 
// static short int myshort = 1; 
// static int myint = 420; 
// static long int mylong = 9999; 
// static char *mystring = "blah"; 
// static int myintarray[2] = { 420, 420 }; 
// static int arr_argc = 0; 
static int fd = 0;

struct vfs_data_t {
	__u32 pid;
	int size;
	__u32 type;
	//const unsigned char *name;
};
 
/* module_param(foo, int, 0000) 
 * The first param is the parameters name. 
 * The second param is its data type. 
 * The final argument is the permissions bits, 
 * for exposing parameters in sysfs (if non-zero) at a later stage. 
//  */ 
// module_param(myshort, short, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP); 
// MODULE_PARM_DESC(myshort, "A short integer"); 
// module_param(myint, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); 
// MODULE_PARM_DESC(myint, "An integer"); 
// module_param(mylong, long, S_IRUSR); 
// MODULE_PARM_DESC(mylong, "A long integer"); 
// module_param(mystring, charp, 0000); 
// MODULE_PARM_DESC(mystring, "A character string"); 
// module_param(fd, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); 
// MODULE_PARM_DESC(fd, "File Descriptor for ebpf map"); 
 
/* module_param_array(name, type, num, perm); 
 * The first param is the parameter's (in this case the array's) name. 
 * The second param is the data type of the elements of the array. 
 * The third argument is a pointer to the variable that will store the number 
 * of elements of the array initialized by the user at module loading time. 
 * The fourth argument is the permission bits. 
 */ 
// module_param_array(myintarray, int, &arr_argc, 0000); 
// MODULE_PARM_DESC(myintarray, "An array of integers"); 



static u32 bpf_map_value_size(const struct bpf_map *map)
{
	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
		return round_up(map->value_size, 8) * num_possible_cpus();
	else if (IS_FD_MAP(map))
		return sizeof(u32);
	else
		return  map->value_size;
}

static unsigned long bpf_map_memory_footprint(const struct bpf_map *map)
{
	unsigned long size;

	size = round_up(map->key_size + bpf_map_value_size(map), 8);

	return round_up(map->max_entries * size, PAGE_SIZE);
}

static void bpf_map_write_active_inc(struct bpf_map *map)
{
	atomic64_inc(&map->writecnt);
}

static void bpf_map_write_active_dec(struct bpf_map *map)
{
	atomic64_dec(&map->writecnt);
}

static void bpf_map_mmap_open(struct vm_area_struct *vma)
{
	struct bpf_map *map = vma->vm_file->private_data;

	if (vma->vm_flags & VM_MAYWRITE)
		bpf_map_write_active_inc(map);
}

static void bpf_map_mmap_close(struct vm_area_struct *vma)
{
	struct bpf_map *map = vma->vm_file->private_data;

	if (vma->vm_flags & VM_MAYWRITE)
		bpf_map_write_active_dec(map);
}


static const struct vm_operations_struct bpf_map_default_vmops = {
	.open		= bpf_map_mmap_open,
	.close		= bpf_map_mmap_close,
};

static int bpf_map_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct bpf_map *map = filp->private_data;
	int err;

	if (!map->ops->map_mmap || map_value_has_spin_lock(map) ||
	    map_value_has_timer(map) || map_value_has_kptrs(map))
		return -ENOTSUPP;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	mutex_lock(&map->freeze_mutex);

	if (vma->vm_flags & VM_WRITE) {
		if (map->frozen) {
			err = -EPERM;
			goto out;
		}
		/* map is meant to be read-only, so do not allow mapping as
		 * writable, because it's possible to leak a writable page
		 * reference and allows user-space to still modify it after
		 * freezing, while verifier will assume contents do not change
		 */
		if (map->map_flags & BPF_F_RDONLY_PROG) {
			err = -EACCES;
			goto out;
		}
	}

	/* set default open/close callbacks */
	vma->vm_ops = &bpf_map_default_vmops;
	vma->vm_private_data = map;
	vma->vm_flags &= ~VM_MAYEXEC;
	if (!(vma->vm_flags & VM_WRITE))
		/* disallow re-mapping with PROT_WRITE */
		vma->vm_flags &= ~VM_MAYWRITE;

	err = map->ops->map_mmap(map, vma);
	if (err)
		goto out;

	if (vma->vm_flags & VM_MAYWRITE)
		bpf_map_write_active_inc(map);
out:
	mutex_unlock(&map->freeze_mutex);
	return err;
}


static __poll_t bpf_map_poll(struct file *filp, struct poll_table_struct *pts)
{
	struct bpf_map *map = filp->private_data;

	if (map->ops->map_poll)
		return map->ops->map_poll(map, filp, pts);

	return EPOLLERR;
}

static ssize_t bpf_dummy_write(struct file *filp, const char __user *buf,
			       size_t siz, loff_t *ppos)
{
	/* We need this handler such that alloc_file() enables
	 * f_mode with FMODE_CAN_WRITE.
	 */
	return -EINVAL;
}

static ssize_t bpf_dummy_read(struct file *filp, char __user *buf, size_t siz,
			      loff_t *ppos)
{
	/* We need this handler such that alloc_file() enables
	 * f_mode with FMODE_CAN_READ.
	 */
	return -EINVAL;
}

struct bpf_map *__bpf_map_get(struct fd f)
{
	if (!f.file)
		return ERR_PTR(-EBADF);
	// if (f.file->f_op != &bpf_map_fops) {
	// 	fdput(f);
	// 	return ERR_PTR(-EINVAL);
	// }

	return f.file->private_data;
}

static void bpf_map_show_fdinfo(struct seq_file *m, struct file *filp)
{
	struct bpf_map *map = filp->private_data;
	u32 type = 0, jited = 0;

	if (map_type_contains_progs(map)) {
		spin_lock(&map->owner.lock);
		type  = map->owner.type;
		jited = map->owner.jited;
		spin_unlock(&map->owner.lock);
	}

	seq_printf(m,
		   "map_type:\t%u\n"
		   "key_size:\t%u\n"
		   "value_size:\t%u\n"
		   "max_entries:\t%u\n"
		   "map_flags:\t%#x\n"
		   "map_extra:\t%#llx\n"
		   "memlock:\t%lu\n"
		   "map_id:\t%u\n"
		   "frozen:\t%u\n",
		   map->map_type,
		   map->key_size,
		   map->value_size,
		   map->max_entries,
		   map->map_flags,
		   (unsigned long long)map->map_extra,
		   bpf_map_memory_footprint(map),
		   map->id,
		   READ_ONCE(map->frozen));
	if (type) {
		seq_printf(m, "owner_prog_type:\t%u\n", type);
		seq_printf(m, "owner_jited:\t%u\n", jited);
	}
}

static void bpf_map_put_uref(struct bpf_map *map)
{
	if (atomic64_dec_and_test(&map->usercnt)) {
		if (map->ops->map_release_uref)
			map->ops->map_release_uref(map);
	}
}

void bpf_map_put_with_uref(struct bpf_map *map)
{
	bpf_map_put_uref(map);
	bpf_map_put(map);
}

static int bpf_map_release(struct inode *inode, struct file *filp)
{
	struct bpf_map *map = filp->private_data;

	if (map->ops->map_release)
		map->ops->map_release(map, filp);

	bpf_map_put_with_uref(map);
	return 0;
}

const struct file_operations bpf_map_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_map_show_fdinfo,
#endif
	.release	= bpf_map_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
	.mmap		= bpf_map_mmap,
	.poll		= bpf_map_poll,
};

static int __init hello_5_init(void) 
{ 


    const void *key;
    const void *next_key;

    const size_t attr_sz = offsetofend(union bpf_attr,next_key); 
    union bpf_attr attr;
    struct fd f;
    struct bpf_map *map;
	struct file *file;
	struct vfs_data_t *data;

    // memset(&attr,0,attr_sz);
    // attr.map_fd = fd;
    // attr.key = (__u64) (unsigned long) key;
    // attr.next_key = (__u64) (unsigned long) next_key;
    file = filp_open("/sys/fs/bpf/write_map", O_RDWR, O_RDWR);

	memset(&f,0,sizeof(struct fd));
	f.file = file;
	f.flags = 1;
	//pr_info("");
	
	//fdlong = sys_open("/sys/fs/bpf/write_map",O_RDONLY);
    map = __bpf_map_get(f);
    if (IS_ERR(map)){
        pr_info("Ret is %d \n",PTR_ERR(map));
        return PTR_ERR(map);        
    }
	bpf_map_inc(map);
	
	fdput(f);
	__u64 keynumber = 0;
	data = map->ops->map_lookup_elem(map,&keynumber);


    return 0; 
} 
 
static void __exit hello_5_exit(void) 
{ 
    pr_info("Goodbye, world 5\n"); 
} 
 
module_init(hello_5_init); 
module_exit(hello_5_exit);