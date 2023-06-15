#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

int uprobing(char *string){
    printf("Uprobing pid %d \n",getpid());
    sleep(5);
}

int main() {
   // printf() displays the string inside quotation
   while(1){

    char string[32] = "String";
    uprobing(string);
    // pthread_t thread_id;
    // pthread_create(&thread_id,NULL,uprobing,NULL);
    // pthread_join(thread_id,NULL);
   }
}
