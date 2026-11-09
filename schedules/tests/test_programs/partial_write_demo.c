/* Demo/validation tool for rose.ko's PARTIAL_WRITE_FAULT kprobe (write_pre_handler
 * in rose.c). Writes a single repeated character to a /tmp file with a single
 * write() call and no retry logic - a naive caller that doesn't handle a
 * short write - so any truncation rose.ko applies shows up directly as a
 * genuinely short file (missing tail bytes entirely, not corrupted-with-
 * garbage).
 *
 * Build:
 *   ./build.sh              (compiles every *.c in this directory)
 *   or directly:
 *   gcc -O0 -Wall -o partial_write_demo partial_write_demo.c
 *
 * Runs unattended, no input needed: sleeps for HEARTBEAT_INTERVAL_SEC *
 * HEARTBEAT_COUNT seconds before the real write below. See
 * schedules/tests/partial_writes_test.yaml, whose begin_condition is a
 * user_function uprobe pinned to the exact instruction of the write() call
 * below (symbol: main, offset: <call site's byte offset from main's entry>,
 * found via objdump - see the yaml's comment) - it fires right as this
 * process is about to make that call. That's safe now that
 * state_processor.bpf.h's inject_fault() arms rose.ko via a direct, in-kernel
 * kfunc call (rose.c's bpf_rose_arm_partial_write()) instead of an async
 * ring-buffer/userspace round trip: a time- or syscall-based condition can't
 * work here, since rose.ko's own kprobe checks target_pid synchronously, in
 * kernel, on the very same syscall the executor uses to notice a satisfied
 * condition - so a condition tied to a syscall the demo itself makes could
 * never win that race for its own triggering syscall against an *async*
 * arm - but a synchronous, in-kernel arm has no such race to lose, and the
 * uprobe doesn't need any syscall from this process to fire at all. Every
 * uprobe hit also logs "UPROBE HIT:[[cond_nr]], PID:[pid]" to the trace_pipe
 * (uprobes.bpf.c's entry()), letting you confirm this fires at the intended
 * write() call and not somewhere else.
 *
 * After the sleep, it issues the single write(), then reads the file back
 * and prints "expected: ..." (the original fill pattern) next to
 * "got: ..." (what's actually on disk, truncated to however many bytes
 * write() actually reported) - they differ whenever the fault fires,
 * regardless of corrupt_buffer, since there's no retry to recover the tail.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define BUF_SIZE 64
#define OUT_PATH "/tmp/partial_write_demo.txt"
#define FILL_CHAR 'A'

#define HEARTBEAT_INTERVAL_SEC 5
#define HEARTBEAT_COUNT 4

int main(void){
    char buf[BUF_SIZE];
    for (int i = 0; i < BUF_SIZE; i++){
        buf[i] = FILL_CHAR;
    }

    /* rose.ko's corrupt_write_tail() pokes 0xEE directly into *this* buffer via
     * copy_to_user (see rose.c) - not just what lands in the file - so buf
     * itself is no longer reliable as "the expected content" once the fault
     * fires. Snapshot it now, before that can happen. */

    sleep(HEARTBEAT_INTERVAL_SEC * HEARTBEAT_COUNT);

    int fd = open(OUT_PATH, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0){
        perror("open");
        return 1;
    }

    ssize_t n = write(fd, buf, BUF_SIZE);
    if (n < 0){
        perror("write");
        close(fd);
        return 1;
    }

    fsync(fd);
    close(fd);

    char readback[BUF_SIZE];
    int rfd = open(OUT_PATH, O_RDONLY);
    if (rfd < 0){
        perror("open (readback)");
        return 1;
    }
    ssize_t rn = read(rfd, readback, BUF_SIZE);
    close(rfd);
    if (rn < 0){
        perror("read (readback)");
        return 1;
    }

    printf("expected: %.*s\n", BUF_SIZE, buf);
    printf("got:      %.*s\n", (int)rn, readback);
    return 0;
}
