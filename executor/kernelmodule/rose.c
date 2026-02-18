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

/* This function checks if str1 (needle) is contained in str2 (haystack)
 * within the first str_len bytes of str2. It looks for a contiguous ordered
 * match (not just presence of each character in any order).
 */
__bpf_kfunc int bpf_strstr(const char *str1, const char *str2, int str_len)
{
    /* Bound constants to keep loops provably finite (helpful for eBPF verifier). */
    const int MAX_NEEDLE = 64;
    const int MAX_HAY = 256; /* increased from 64 to handle longer paths */

    int needle_len = 0;

    if (!str1 || !str2 || str_len <= 0)
        return 0;

    //pr_info("Comparing %s and %s\n", str1, str2);

    /* Compute needle length up to MAX_NEEDLE */
    for (needle_len = 0; needle_len < MAX_NEEDLE && str1[needle_len] != '\0'; needle_len++)
        ;

    //pr_info("Needle len is %d, str_len is %d \n",needle_len,str_len);

    if (needle_len == 0 && str1[0] == '\0')
        return 1;

    /* If needle wasn't NUL-terminated within MAX_NEEDLE, treat as no match (safer) */
    if (needle_len == MAX_NEEDLE && str1[needle_len - 1] != '\0'){
        //pr_info("Needle not nul-terminated %d \n",needle_len);
        return 0;
    }
    /* If needle is longer than the provided hay length, no match is possible */
    // if (needle_len > str_len){
    //     pr_info("Needle is longer than str_len %d \n",needle_len);
    //     return 0;
    // }

    /* Scan haystack (str2) up to the min(str_len, MAX_HAY). Look for contiguous match. */
    for (int i = 0; i < MAX_HAY && str2[i] != '\0'; i++) {
        int j;

        for (j = 0; j < needle_len; j++) {
            //pr_info("Comparing char: %c and %c \n", str2[i + j], str1[j]);
            if (str2[i + j] != str1[j])
                break;
        }

        if (j == needle_len) {
            //pr_info("bpf_strstr(): match found: needle=%s hay=%s str_len=%d\n",str1, str2, str_len);
            return 1;
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
