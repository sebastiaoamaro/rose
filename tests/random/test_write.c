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
   while(1){

    char string[6] = "String";
    
    int fd = openat(-100,"teste.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    printf("OPEN result is %d errno is %d\n",fd,errno);


   int res = write(fd,string,sizeof(string));
   printf("WRITE result is %d errno is %d count is %d\n",res,errno,count);

   close(fd);


   int fd_read = open("teste.txt", O_CREAT | O_RDWR, 0644);
   unsigned char read_string[6];

   int res_read = read(fd_read,&read_string,6);
   printf("READ result is %d errno is %d count is %d result is %s \n",res_read,errno,count,read_string);
    //fdatasync(fd);

   close(fd);

    fflush(stdout);
    // pthread_t thread_id;
    // pthread_create(&thread_id,NULL,uprobing,NULL);
    // pthread_join(thread_id,NULL);
    count++;
    sleep(1);
   }
}
