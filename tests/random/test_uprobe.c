#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

static int count = 0;
int uprobing(char *string){
    printf("Uprobing count %d \n",count);
    fflush(stdout);
    printf("Flushed %d \n",count);
    count++;
}

int main() {
   // printf() displays the string inside quotation
   printf("Pid %d \n",getpid());
   while(1){

    // char string[7] = "String";
    
    // int fd = openat(-100,"teste.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    // printf("OPEN result is %d errno is %d\n",fd,errno);

    // int res = write(fd,string,sizeof(string));
    // printf("%d errno is %d\n",res,errno);
    // pthread_t thread_id;
    // pthread_create(&thread_id,NULL,uprobing,NULL);
    // pthread_join(thread_id,NULL);
    uprobing("xd");
    
    sleep(1);
   }
}
