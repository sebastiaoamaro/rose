#include <linux/init.h>       // Macros for module initialization
#include <linux/module.h>     // Core header for loading modules
#include <linux/kernel.h>     // Kernel logging macros
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/string.h>

/* Declare the kfunc prototype */
__bpf_kfunc int bpf_strstr(const char* str1,const char* str2,int str_len);

/* Begin kfunc definitions */
__bpf_kfunc_start_defs();

/* Define the bpf_strstr kfunc */
__bpf_kfunc int bpf_strstr(const char* str1,const char* str2,int str_len)
{
    //printk(KERN_INFO "Comparing %s and %s \n", str1, str2);

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
    }
    return 0;
}

/* End kfunc definitions */
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

/* Register the kfunc ID set */
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};


MODULE_LICENSE("GPL");
MODULE_AUTHOR("SA");
MODULE_DESCRIPTION("Rose Kernel Module");
MODULE_VERSION("1.0");
