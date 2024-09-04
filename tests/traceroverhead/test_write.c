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

void my_test_function();
static void sig_handler(int sig)
{
	start = 1;
	printf("Starting workload \n");
	fflush(stdout);
}

int main(int argc, char *argv[]) {
   // printf() displays the string inside quotation
    //printf("Pid %d \n",getpid());
    int fd = open("teste.txt", O_CREAT | O_RDWR, 0644);
    int count = 0;
    int workload_size = 10000000;
    //int workload_size = 10000;

    char *tracing_type;
    if (argc > 1){
        tracing_type = malloc(strlen(argv[1]) + 1);
        strcpy(tracing_type, argv[1]);
    }else{
        tracing_type = malloc(strlen("test") + 1);
        strcpy(tracing_type, "test");
    }

    signal(SIGUSR1, sig_handler);

    while(!start){
        continue;
    }
    time_t start_time = time(NULL);
    char string[15];

    for(int i=0;i < workload_size;i++){

        //generateRandomString(string,15);

        //int res = write(fd,string,sizeof(string));

        int fd = open("teste.txt", O_CREAT | O_RDWR, 0644);

        close(fd);

   }
    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);
    printf("In tracing:%s Elapsed time: %.2f seconds\n",tracing_type, elapsed_time);
    fflush(stdout);

}

void generateRandomString(char *str, int length) {
    char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int charsetSize = sizeof(charset) - 1;

    for (int i = 0; i < length; i++) {
        int key = rand() % charsetSize;
        str[i] = charset[key];
    }

    str[length] = '\0';  // Null-terminate the string
}

void my_test_function(){
    int counter = 0;
    counter++;
}
