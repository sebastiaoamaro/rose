/* Demo/validation tool for rose/executor's new MSYNC_FAULT kprobe
 * (__x64_sys_msync handler in fault_inject.bpf.c).
 *
 * mmaps a file MAP_SHARED, writes into the mapping, then calls msync()
 * in a loop, printing each call's return value/errno. Unlike
 * partial_write_demo.c this uses a plain "syscall" error-injection fault
 * (process_current_state()/inject_fault(), the same mechanism as every
 * other syscall_error fault e.g. madvise), not rose.ko's synchronous
 * kfunc arm - so a time-based begin_condition works fine here, no uprobe
 * race to worry about. See schedules/tests/msync_test.yaml, whose fault
 * fires on a `type: time` condition partway through the loop below.
 *
 * Build:
 *   ./build.sh              (compiles every *.c in this directory)
 *   or directly:
 *   gcc -O0 -Wall -o msync_demo msync_demo.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#define OUT_PATH "/tmp/msync_demo.mmap"
#define MAP_SIZE 4096
#define LOOP_COUNT 20
#define LOOP_INTERVAL_SEC 1

int main(void){
    int fd = open(OUT_PATH, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0){
        perror("open");
        return 1;
    }
    if (ftruncate(fd, MAP_SIZE) < 0){
        perror("ftruncate");
        close(fd);
        return 1;
    }

    char *map = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED){
        perror("mmap");
        close(fd);
        return 1;
    }
    memset(map, 'A', MAP_SIZE);

    for (int i = 0; i < LOOP_COUNT; i++){
        errno = 0;
        int rc = msync(map, MAP_SIZE, MS_SYNC);
        printf("msync[%d] -> rc=%d errno=%d (%s)\n", i, rc, errno, strerror(errno));
        fflush(stdout);
        sleep(LOOP_INTERVAL_SEC);
    }

    munmap(map, MAP_SIZE);
    close(fd);
    return 0;
}
