#include <linux/init.h>       // Macros for module initialization
#include <linux/module.h>     // Core header for loading modules
#include <linux/kernel.h>     // Kernel logging macros
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/string.h>

/* Declare the kfunc prototype */
__bpf_kfunc int bpf_strstr(const char* str1,const char* str2,int str_len);

__bpf_kfunc int bpf_compare_str(const char* str1,const char* str2,int str_len);

/* Begin kfunc definitions */
__bpf_kfunc_start_defs();

/* Define the bpf_strstr kfunc */
__bpf_kfunc int bpf_strstr(const char* str1,const char* str2,int str_len)
{
    //printk(KERN_INFO "Comparing %s and %s \n", str1, str2);

    //size_t count = 0;
    int found_end = 0;
    for (size_t i = 0; i < 64; i++)
    {
        if (str2[i] == '\0'){
            found_end = i;
        }

    }
    int count = 0;
    for (int i = 0; i < found_end; ++i){
        if (str1[count] == str2[i] ){
            //printk(KERN_INFO "%c and %c \n",comparand[count],comparand2[i]);
            count++;
            if(str_len == count){
                printk(KERN_INFO "They are equal str_len is %d \n",str_len);
                return 1;
            }
            continue;
        }else{
            count = 0;
        }
        // if(str_len == count){
        //     bpf_printk("They are equal str_len is %d \n",str_len);
        //     return true;
        // }
    }


    // Return -1 if the substring is not found
    return 0;
}

__bpf_kfunc int bpf_compare_str(const char* str1,const char* str2,int str_len)
{
    //printk(KERN_INFO "In Function! string is %s \n", str2);

    int count = 0;
    for (int i = 0; i < str_len; ++i){
        if (str1[count] == str2[i] ){
            // bpf_printk("%c and %c \n",comparand[count],comparand2[i]);
            count++;
            if(str_len == count){
                printk(KERN_INFO "They are equal str_len is %d \n",str_len);
                return 1;
            }
            continue;
        }else{
            count = 0;
        }
        // if(str_len == count){
        //     bpf_printk("They are equal str_len is %d \n",str_len);
        //     return true;
        // }
    }


    // Return -1 if the substring is not found
    return 0;
}

/* End kfunc definitions */
__bpf_kfunc_end_defs();

/* Define the BTF kfuncs ID set */
BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_ID_FLAGS(func, bpf_compare_str)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

/* Register the kfunc ID set */
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/* Function executed when the module is loaded */
static int __init hello_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, world!\n");
    /* Register the BTF kfunc ID set for BPF_PROG_TYPE_KPROBE */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("bpf_kfunc_example: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_example: Module loaded successfully\n");
    return 0; // Return 0 if successful
}

/* Function executed when the module is removed */
static void __exit hello_exit(void)
{
    /* Unregister the BTF kfunc ID set */
    //unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    printk(KERN_INFO "Goodbye, world!\n");
}

/* Macros to define the module’s init and exit points */
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");                 // License type (GPL)
MODULE_AUTHOR("Your Name");            // Module author
MODULE_DESCRIPTION("A simple module"); // Module description
MODULE_VERSION("1.0");                 // Module version
