#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SA");
MODULE_DESCRIPTION("eBPF kfunc module providing bpf_strstr");
MODULE_VERSION("1.0");

/* === Genuine partial-write fault via a native kprobe ===
 * Unlike the BPF-based fault injection in fault_inject.bpf.c (which can only
 * skip __x64_sys_write entirely via bpf_override_return), a kprobe registered
 * directly through the kernel's own kprobe API - not as BPF bytecode - can
 * freely write pt_regs fields in its pre_handler. That's ordinary, always-
 * supported kprobe usage; the BPF verifier's read-only restriction on kprobe
 * ctx only applies to verified BPF bytecode, not to native kernel module code.
 *
 * __x64_sys_write's own single parameter is a pointer (in the outer regs' di
 * field) to the *real* syscall pt_regs holding fd/buf/count in di/si/dx. We
 * mutate that inner struct's dx (count) before returning, so the real
 * function body - which hasn't executed yet - reads back our reduced count
 * and performs a genuine, self-consistent short write: exactly the first
 * partial_count bytes of buf are what actually reach the file.
 *
 * By default this only truncates the count, for a faithful short-write
 * emulation - a real short write() never touches the caller's buffer at all,
 * so a correct retry recovers the full, correct data. Optionally
 * (corrupt_buffer != 0) we also scribble a garbage pattern over
 * buf[partial_count:orig_count) - the tail the app didn't get to send this
 * call. A correct caller reacts to a short write by retrying
 * write(fd, buf + n, count - n) against the *same* buffer; since that tail is
 * now corrupted in place, the retry persists garbage instead of the original
 * data even though the app did everything "right" (checked the return value,
 * resumed from the right offset) - a different, more contrived failure mode
 * than a real short write. Also distinct from LazyFS's torn-op, which
 * persists/drops caller-specified byte ranges but never touches the source
 * buffer's content.
 *
 * Fires at most once, only for a pid armed via the target_pid module
 * parameter. Wired into the BPF fault-condition system via
 * PARTIAL_WRITE_FAULT (state_processor.bpf.h / executor.c's handle_event).
 *
 * Each fault is armed with a (pid, tid) pair - see rose_target_matches(). The
 * BPF side passes the thread that hit the target line's uprobe as tid, so the
 * syscall that fails is the one that execution issues, not another thread's.
 */
static int target_pid = 0;
static int target_tid = 0;
static int partial_count = -1;
static int corrupt_buffer = 0;

module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "pid to truncate the next write() from (0 = disabled)");
module_param(target_tid, int, 0644);
MODULE_PARM_DESC(target_tid, "thread of target_pid to truncate the next write() from (0 = any thread)");
module_param(partial_count, int, 0644);
MODULE_PARM_DESC(partial_count, "byte count to shrink that write() to");
module_param(corrupt_buffer, int, 0644);
MODULE_PARM_DESC(corrupt_buffer, "0: truncate count only, buffer untouched (default). 1: also poison buf's un-sent tail with 0xEE");

/* Repeating byte used to stomp the un-sent tail of the write buffer - chosen to be
 * visibly-wrong in a hexdump/log rather than a plausible value like 0x00. */
#define CORRUPTION_BYTE 0xEE
/* Bounds the per-arm copy_to_user work (and the on-stack staging buffer),
 * independent of how large a write() count callers may pass. */
#define MAX_CORRUPT_BYTES 4096

/* Does the current syscall belong to the armed target? pid is a process id
 * (tgid) and tid a thread id - the kernel calls them current->tgid and
 * current->pid respectively. With a tid, only that thread matches: the
 * execution that hit the target line. tid == 0 means the arming side didn't
 * know the thread (fault armed from another process), so any thread of pid
 * matches. */
static bool rose_target_matches(int pid, int tid)
{
    if (pid == 0)
        return false;
    if (tid)
        return current->pid == tid;
    return current->tgid == pid;
}

/* Shared by write's tail-poisoning and torn-read's in-range corruption -
 * both just need "scribble CORRUPTION_BYTE over buf[from,to) and say how much
 * actually landed." Returns the number of bytes actually poisoned (may be
 * less than to-from if copy_to_user faults partway through). */
static long poison_user_range(char __user *buf, int from, long to)
{
    char garbage[128];
    long remaining = to - from;
    long done = 0;

    if (remaining > MAX_CORRUPT_BYTES)
        remaining = MAX_CORRUPT_BYTES;

    memset(garbage, CORRUPTION_BYTE, sizeof(garbage));

    while (done < remaining) {
        long chunk = remaining - done;
        if (chunk > (long)sizeof(garbage))
            chunk = sizeof(garbage);
        if (copy_to_user(buf + from + done, garbage, chunk)) {
            pr_warn("rose: buffer corruption stopped early at +%ld (copy_to_user fault)\n", done);
            break;
        }
        done += chunk;
    }

    return done;
}

static void corrupt_write_tail(char __user *buf, int from, long to)
{
    long done = poison_user_range(buf, from, to);

    pr_info("rose: corrupted %ld tail byte(s) of write buffer at +%d\n", done, from);
}

static int write_pre_handler(struct kprobe *p, struct pt_regs *ctx)
{
    struct pt_regs *inner_regs;
    long orig_count;
    long new_count;

    if (!rose_target_matches(target_pid, target_tid))
        return 0;

    if (partial_count < 0)
        return 0;

    /* __x64_sys_write(const struct pt_regs *regs) - its one argument (a
     * pointer to the real syscall regs) arrives in the outer trap's di. */
    inner_regs = (struct pt_regs *) ctx->di;
    if (!inner_regs)
        return 0;

    /* Truncate to partial_count, capped at orig_count - 1 so the write is always
     * genuinely short: a fixed partial_count would silently no-op on writes of
     * partial_count bytes or fewer (e.g. etcd's 8-byte length prefixes). At least
     * one byte is kept, so a 1-byte write passes through untouched - unless
     * partial_count is explicitly 0 (write nothing). */
    orig_count = inner_regs->dx;
    new_count = min_t(long, partial_count, orig_count - 1);
    if (orig_count > 0 && (new_count > 0 || partial_count == 0)) {
        if (corrupt_buffer)
            corrupt_write_tail((char __user *) inner_regs->si, new_count, orig_count);

        inner_regs->dx = new_count;
        pr_info("rose: partial write pid=%d tid=%d count %ld -> %ld (corrupt_buffer=%d)\n",
                current->tgid, current->pid, orig_count, new_count, corrupt_buffer);
    }

    /* Fire once per arm. */
    target_pid = 0;
    target_tid = 0;

    return 0;
}

static struct kprobe write_kp = {
    .symbol_name = "__x64_sys_write",
    .pre_handler = write_pre_handler,
};
static bool write_kp_registered = false;

/* === Genuine partial-read fault: mirrors write_pre_handler above, but for
 * __x64_sys_read. Truncating the count before the real read() body runs
 * means it only copy_to_user()s that many bytes - a genuine short read, with
 * the untouched remainder of buf simply whatever was there before the call
 * (uninitialized from the caller's perspective either way, since they can't
 * trust past their own return-value check). Unlike partial write, there's no
 * corrupt_buffer-style toggle here: poisoning bytes beyond the returned count
 * wouldn't fool a correct caller, who already knows not to trust them - see
 * torn_read below for the read-side equivalent of an insidious fault. */
static int target_pid_read = 0;
static int target_tid_read = 0;
static int partial_read_count = -1;

module_param(target_pid_read, int, 0644);
MODULE_PARM_DESC(target_pid_read, "pid to truncate the next read() from (0 = disabled)");
module_param(target_tid_read, int, 0644);
MODULE_PARM_DESC(target_tid_read, "thread of target_pid_read to truncate the next read() from (0 = any thread)");
module_param(partial_read_count, int, 0644);
MODULE_PARM_DESC(partial_read_count, "byte count to shrink that read() to");

static int read_pre_handler(struct kprobe *p, struct pt_regs *ctx)
{
    struct pt_regs *inner_regs;
    long orig_count;

    if (!rose_target_matches(target_pid_read, target_tid_read))
        return 0;

    if (partial_read_count < 0)
        return 0;

    /* __x64_sys_read(const struct pt_regs *regs) - same outer-trap-pointer
     * calling convention as __x64_sys_write; see write_pre_handler above. */
    inner_regs = (struct pt_regs *) ctx->di;
    if (!inner_regs)
        return 0;

    orig_count = inner_regs->dx;
    if (partial_read_count < orig_count) {
        inner_regs->dx = partial_read_count;
        pr_info("rose: partial read pid=%d tid=%d count %ld -> %d\n",
                current->tgid, current->pid, orig_count, partial_read_count);
    }

    /* Fire once per arm. */
    target_pid_read = 0;
    target_tid_read = 0;

    return 0;
}

static struct kprobe read_kp = {
    .symbol_name = "__x64_sys_read",
    .pre_handler = read_pre_handler,
};
static bool read_kp_registered = false;

/* === Torn-read fault: the read()-side mirror of a real disk failure -
 * silently wrong data despite the syscall reporting full success - rather
 * than a truncated count (see the design discussion this followed: real
 * disk failures rarely manifest as short reads; they're either an outright
 * I/O error, or - the interesting case here - data that's silently wrong
 * while everything *looks* like it succeeded).
 *
 * This needs a kretprobe, not a pre_handler: the real read() must actually
 * complete (copying genuine data into the caller's buffer) before there's
 * anything meaningful to corrupt. entry_handler stashes the buf pointer at
 * call time (from the same outer-trap inner_regs as above); the return
 * handler runs once __x64_sys_read is about to return, with the real,
 * final byte count already computed - poisons buf[torn_read_offset:n) in
 * place, then lets the syscall return that same (unmodified, still fully
 * "successful") count regardless. */
struct torn_read_call_data {
    char __user *buf;
};

static int target_pid_torn_read = 0;
static int target_tid_torn_read = 0;
static int torn_read_offset = -1;

module_param(target_pid_torn_read, int, 0644);
MODULE_PARM_DESC(target_pid_torn_read, "pid to corrupt the next read() from (0 = disabled)");
module_param(target_tid_torn_read, int, 0644);
MODULE_PARM_DESC(target_tid_torn_read, "thread of target_pid_torn_read to corrupt the next read() from (0 = any thread)");
module_param(torn_read_offset, int, 0644);
MODULE_PARM_DESC(torn_read_offset, "offset within the returned bytes to start poisoning from");

static int torn_read_entry_handler(struct kretprobe_instance *ri, struct pt_regs *ctx)
{
    struct torn_read_call_data *data = (struct torn_read_call_data *) ri->data;
    struct pt_regs *inner_regs;

    if (!rose_target_matches(target_pid_torn_read, target_tid_torn_read))
        return 1; /* non-zero: skip instrumenting this call */

    if (torn_read_offset < 0)
        return 1;

    inner_regs = (struct pt_regs *) ctx->di;
    if (!inner_regs)
        return 1;

    data->buf = (char __user *) inner_regs->si;
    return 0;
}

static int torn_read_ret_handler(struct kretprobe_instance *ri, struct pt_regs *ctx)
{
    struct torn_read_call_data *data = (struct torn_read_call_data *) ri->data;
    long actual_read = regs_return_value(ctx);
    long done;

    if (actual_read <= 0 || torn_read_offset >= actual_read)
        goto out;

    done = poison_user_range(data->buf, torn_read_offset, actual_read);
    pr_info("rose: torn read pid=%d tid=%d corrupted %ld byte(s) of the returned %ld at +%d - read() still reports success\n",
            current->tgid, current->pid, done, actual_read, torn_read_offset);

out:
    /* Fire once per arm. */
    target_pid_torn_read = 0;
    target_tid_torn_read = 0;
    return 0;
}

static struct kretprobe torn_read_krp = {
    .handler = torn_read_ret_handler,
    .entry_handler = torn_read_entry_handler,
    .data_size = sizeof(struct torn_read_call_data),
    .maxactive = 20,
    .kp = {
        .symbol_name = "__x64_sys_read",
    },
};
static bool torn_read_krp_registered = false;

/* === Define the BPF kfunc === */
__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_strstr(const char *str1, const char *str2, int str_len)
{
    /* Bound constants to keep loops provably finite (helpful for eBPF verifier). */
    const int MAX_NEEDLE = 64;
    const int MAX_HAY = 256; /* increased from 64 to handle longer paths */

    int needle_len = 0;

    if (!str1 || !str2 || str_len <= 0)
        return 0;


    /* Compute needle length up to MAX_NEEDLE */
    for (needle_len = 0; needle_len < MAX_NEEDLE && str1[needle_len] != '\0'; needle_len++)
        ;


    if (needle_len == 0 && str1[0] == '\0')
        return 1;

    /* If needle wasn't NUL-terminated within MAX_NEEDLE, treat as no match (safer) */
    if (needle_len == MAX_NEEDLE && str1[needle_len - 1] != '\0'){
        //pr_info("Needle not nul-terminated %d \n",needle_len);
        return 0;
    }
    for (int i = 0; i < MAX_HAY && str2[i] != '\0'; i++) {
        int j;

        for (j = 0; j < needle_len; j++) {
            if (str2[i + j] != str1[j])
                break;
        }

        if (j == needle_len) {
            return 1;
        }
    }

    return 0;
}

/* Arms the partial-write kprobe above, called directly from the tracer's own
 * BPF kprobe on __x64_sys_write (state_processor.bpf.h's inject_fault(),
 * PARTIAL_WRITE_FAULT branch) the instant its fault conditions are satisfied.
 * This used to be done from userspace, via a ring-buffer event relayed
 * through a poll loop into a write() on this module's sysfs parameters -
 * strictly slower than write_pre_handler's own, synchronous, in-kernel check
 * on that same syscall, so the syscall that satisfied the conditions could
 * never be the one that got corrupted. A kfunc call happens synchronously,
 * in the same kprobe chain, on the same CPU: since new kprobes are inserted
 * at the head of a shared address's handler list and dispatched head-first
 * (kernel/kprobes.c's add_new_kprobe()/aggr_pre_handler()), and this module
 * is loaded (registering write_kp) before the tracer attaches its own kprobe
 * to the same address, the tracer's handler - and this call - always runs
 * before write_pre_handler for the exact same invocation. */
/* `tid` is the thread that triggered the arming (0 = unknown, match any thread of
 * `pid`) - see rose_target_matches(). target_pid is written last: a non-zero pid
 * is what enables the handler, so it never sees a new pid with a stale tid. */
__bpf_kfunc void bpf_rose_arm_partial_write(int pid, int tid, int count, int corrupt)
{
    partial_count = count;
    corrupt_buffer = corrupt;
    target_tid = tid;
    target_pid = pid;
}

/* Arms read_pre_handler - same synchronous, in-kernel, same-syscall-chain
 * reasoning as bpf_rose_arm_partial_write() above. */
__bpf_kfunc void bpf_rose_arm_partial_read(int pid, int tid, int count)
{
    partial_read_count = count;
    target_tid_read = tid;
    target_pid_read = pid;
}

/* Arms the torn_read_krp kretprobe above. */
__bpf_kfunc void bpf_rose_arm_torn_read(int pid, int tid, int offset)
{
    torn_read_offset = offset;
    target_tid_torn_read = tid;
    target_pid_torn_read = pid;
}

__bpf_kfunc_end_defs();

/* === Register the function in a kfunc ID set === */
BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_ID_FLAGS(func, bpf_rose_arm_partial_write)
BTF_ID_FLAGS(func, bpf_rose_arm_partial_read)
BTF_ID_FLAGS(func, bpf_rose_arm_torn_read)
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
    if (ret) {
        pr_err("Failed to register kfunc set: %d\n", ret);
        return ret;
    }
    pr_info("bpf_strstr() registered as kfunc successfully\n");

    /* Non-fatal: these are separate prototype features, and bpf_strstr's kfunc
     * registration above must still take effect (module load is all-or-
     * nothing) even if any of these fail to find/probe their symbol on this
     * kernel. */
    ret = register_kprobe(&write_kp);
    if (ret) {
        pr_err("Failed to register write_kp kprobe: %d (partial-write prototype disabled)\n", ret);
    } else {
        write_kp_registered = true;
        pr_info("rose: write_kp kprobe registered\n");
    }

    ret = register_kprobe(&read_kp);
    if (ret) {
        pr_err("Failed to register read_kp kprobe: %d (partial-read prototype disabled)\n", ret);
    } else {
        read_kp_registered = true;
        pr_info("rose: read_kp kprobe registered\n");
    }

    ret = register_kretprobe(&torn_read_krp);
    if (ret) {
        pr_err("Failed to register torn_read_krp kretprobe: %d (torn-read prototype disabled)\n", ret);
    } else {
        torn_read_krp_registered = true;
        pr_info("rose: torn_read_krp kretprobe registered\n");
    }

    return 0;
}

static void __exit bpf_kfunc_example_exit(void)
{
    if (write_kp_registered)
        unregister_kprobe(&write_kp);
    if (read_kp_registered)
        unregister_kprobe(&read_kp);
    if (torn_read_krp_registered)
        unregister_kretprobe(&torn_read_krp);
    pr_info("bpf_strstr() module unloaded\n");
}

module_init(bpf_kfunc_example_init);
module_exit(bpf_kfunc_example_exit);
