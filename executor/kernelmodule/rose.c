#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SA");
MODULE_DESCRIPTION("Example eBPF kfunc module providing bpf_strstr");
MODULE_VERSION("1.0");

/* === Define the BPF kfunc === */
__bpf_kfunc_start_defs();

/* This function checks if str2 is contained in str1 up to str_len characters */
__bpf_kfunc int bpf_strstr(const char *str1, const char *str2, int str_len)
{
    int found_end = 0;

    for (size_t i = 0; i < 64; i++) {
        if (str2[i] == '\0') {
            found_end = i;
            break;
        }
    }

    for (int i = 0; i < str_len && str1[i] != '\0'; i++) {
        int j = 0;
        while (i + j < str_len && str1[i + j] == str2[j]) {
            j++;
            if (j == found_end) {
                pr_info("bpf_strstr(): match found between %s and %s, str_len=%d\n",str1,str2, str_len);
                return 1;
            }
        }
    }
    return 0;
}

__bpf_kfunc_end_defs();

/* === Register the function in a kfunc ID set === */
BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

/* === Declare and register the ID set === */
static const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/* === Module init/exit === */
static int __init bpf_kfunc_example_init(void)
{
    int ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret)
        pr_err("Failed to register kfunc set: %d\n", ret);
    else
        pr_info("bpf_strstr() registered as kfunc successfully\n");
    return ret;
}

static void __exit bpf_kfunc_example_exit(void)
{
    pr_info("bpf_strstr() module unloaded\n");
}

module_init(bpf_kfunc_example_init);
module_exit(bpf_kfunc_example_exit);
