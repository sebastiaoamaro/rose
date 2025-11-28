#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdlib.h>

int main(void) {
    printf("Pid %d\n", (int)getpid());

    int count = 0;
    char string[] = "String";

    /* Use libc's syscall() function to call syscalls by number */
    long fd = syscall(SYS_openat, AT_FDCWD, "teste.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    printf("openat -> %ld errno=%d\n", fd, errno);

    if (fd != -1) {
        long written = syscall(SYS_write, fd, string, sizeof(string));
        printf("write -> %ld errno=%d count=%d\n", written, errno, count);

        syscall(SYS_close, fd);
    } else {
        /* optional: print error */
        perror("openat failed");
    }

    long fd_read = syscall(SYS_openat, AT_FDCWD, "teste.txt", O_RDONLY | O_CREAT, 0644);
    unsigned char read_string[16] = {0};

    if (fd_read != -1) {
        long r = syscall(SYS_read, fd_read, read_string, sizeof(read_string) - 1);
        if (r >= 0) read_string[r < (long)sizeof(read_string) ? r : (long)sizeof(read_string)-1] = '\0';
        printf("read -> %ld errno=%d count=%d result=\"%s\"\n", r, errno, count, read_string);
        syscall(SYS_close, fd_read);
    } else {
        perror("openat (read) failed");
    }

    fflush(stdout);
    return 0;
}
