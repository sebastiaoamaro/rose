/* Demo/validation tool for rose.ko's PARTIAL_READ_FAULT (read_pre_handler) and
 * TORN_READ_FAULT (torn_read_krp kretprobe). Writes a known, fixed-pattern
 * source file, pre-fills its own destination buffer with a distinct
 * placeholder byte (so "untouched" is visually distinguishable from both the
 * real pattern and rose.ko's corruption byte), then reads the source file
 * back into that buffer with a single read() call and no retry logic - so
 * any effect rose.ko has is directly visible:
 *
 *   PARTIAL_READ_FAULT: read() returns fewer bytes than requested; buf[0:n)
 *   is real data, buf[n:BUF_SIZE) is still the untouched placeholder - a
 *   genuine short read.
 *
 *   TORN_READ_FAULT: read() still reports the full BUF_SIZE as successfully
 *   read, but buf[offset:BUF_SIZE) has been silently poisoned with rose.ko's
 *   0xEE marker instead of the real source data - the read()-side mirror of
 *   a real disk failure (success reported, data silently wrong).
 *
 * Build:
 *   ./build.sh              (compiles every *.c in this directory)
 *   or directly:
 *   gcc -O0 -Wall -o partial_read_demo partial_read_demo.c
 *
 * Runs unattended: writes the source file, sleeps for HEARTBEAT_INTERVAL_SEC *
 * HEARTBEAT_COUNT seconds, then does the single read() and prints
 * "read() returned N/BUF_SIZE" followed by "expected: ..." (the known source
 * pattern) next to "got: ..." (the full destination buffer, still showing
 * the placeholder wherever read() didn't touch it).
 *
 * See schedules/tests/partial_reads_test.yaml / torn_reads_test.yaml, whose
 * begin_condition is a user_function uprobe pinned to the exact instruction
 * of the read() call below (symbol: main, offset: <found via objdump - see
 * the yaml's comment>) - it fires right as this process is about to make
 * that call, arming the matching rose.ko kfunc synchronously, in-kernel (see
 * partial_write_demo.c / partial_writes_test.yaml for the full design
 * rationale, which applies identically here).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define BUF_SIZE 64
#define SRC_PATH "/tmp/partial_read_demo_src.txt"
#define FILL_CHAR 'A'
#define PLACEHOLDER_CHAR '?'

#define HEARTBEAT_INTERVAL_SEC 5
#define HEARTBEAT_COUNT 4

int main(void){
    char expected[BUF_SIZE];
    for (int i = 0; i < BUF_SIZE; i++){
        expected[i] = FILL_CHAR;
    }

    int wfd = open(SRC_PATH, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (wfd < 0){
        perror("open (source, write)");
        return 1;
    }
    if (write(wfd, expected, BUF_SIZE) != BUF_SIZE){
        perror("write (source)");
        close(wfd);
        return 1;
    }
    close(wfd);

    char buf[BUF_SIZE];
    for (int i = 0; i < BUF_SIZE; i++){
        buf[i] = PLACEHOLDER_CHAR;
    }

    sleep(HEARTBEAT_INTERVAL_SEC * HEARTBEAT_COUNT);

    int fd = open(SRC_PATH, O_RDONLY);
    if (fd < 0){
        perror("open (source, read)");
        return 1;
    }

    ssize_t n = read(fd, buf, BUF_SIZE);
    close(fd);
    if (n < 0){
        perror("read");
        return 1;
    }

    printf("read() returned %zd/%d\n", n, BUF_SIZE);
    printf("expected: %.*s\n", BUF_SIZE, expected);
    printf("got:      %.*s\n", BUF_SIZE, buf);
    return 0;
}
