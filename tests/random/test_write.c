#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

static int count = 0;

int main() {
   // printf() displays the string inside quotation
    printf("Pid %d \n",getpid());
    int fd = open("teste.txt", O_CREAT | O_RDWR, 0644);
    int count = 0;

    char string[6] = "String";

    for (int i=0;i<5;i++){
        int res = write(fd,string,sizeof(string));
        printf("WRITE result is %d errno is %d count is %d\n",res,errno,count);

        close(fd);


        int fd_read = open("teste.txt", O_CREAT | O_RDWR, 0644);
        unsigned char read_string[6];

        int res_read = read(fd_read,&read_string,6);
        printf("READ result is %d errno is %d count is %d result is %s \n",res_read,errno,count,read_string);

        close(fd);

        fflush(stdout);

        count++;
        sleep(1);
    }
}
