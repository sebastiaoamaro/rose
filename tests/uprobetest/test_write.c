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
    printf("Pid %d \n",getpid());
    int workload_size = 100000000000;

    char *tracing_type;
    if (argc > 1){
        tracing_type = malloc(strlen(argv[1]) + 1);
        strcpy(tracing_type, argv[1]);
    }else{
        tracing_type = malloc(strlen("test") + 1);
        strcpy(tracing_type, "test");
    }

    for(int i=0;i < workload_size;i++){
        my_test_function();
        sleep(10);
   }

}

void my_test_function(){
    //printf("Running \n");
    fflush(stdout);
    sleep(10);
}
