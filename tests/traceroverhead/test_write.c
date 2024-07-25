#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <string.h>

static int count = 0;
static int start = 0;
static void sig_handler(int sig)
{
	start = 1;
	//printf("Starting workload \n");
	fflush(stdout);
}

int main(int argc, char *argv[]) {
   // printf() displays the string inside quotation
    //printf("Pid %d \n",getpid());
    int fd = open("teste.txt", O_CREAT | O_RDWR, 0644);
    int count = 0;
    int workload_size = 10000000;

    char *tracing_type = malloc(strlen(argv[1]) + 1);
    strcpy(tracing_type, argv[1]);

    signal(SIGUSR1, sig_handler);

    while(!start){
        continue;
    }
    time_t start_time = time(NULL);
    for(int i=0;i < workload_size;i++){

        char string[6] = "String";

        int fd = openat(-100,"teste.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        //printf("OPEN result is %d errno is %d\n",fd,errno);


        int res = write(fd,string,sizeof(string));
        //printf("WRITE result is %d errno is %d count is %d\n",res,errno,count);

        close(fd);

        int fd_read = open("teste.txt", O_CREAT | O_RDWR, 0644);
        unsigned char read_string[6];

        int res_read = read(fd_read,&read_string,6);
        //printf("READ result is %d errno is %d count is %d result is %s \n",res_read,errno,count,read_string);
            //fdatasync(fd);

        close(fd);

   }
    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);
    printf("In tracing:%s Elapsed time: %.2f seconds\n",tracing_type, elapsed_time);
    fflush(stdout);

}
