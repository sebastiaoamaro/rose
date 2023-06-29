#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
int uprobing(char *string){
    printf("Uprobing pid %d \n",getpid());
    sleep(5);
}

int main() {
   // printf() displays the string inside quotation
   printf("Pid %d \n",getpid());
   while(1){

    char string[32] = "String";
    FILE *fptr;
    fptr = fopen("test.txt","a");
    fprintf(fptr,"%s",string);
    fclose(fptr);
    sleep(5);
    // pthread_t thread_id;
    // pthread_create(&thread_id,NULL,uprobing,NULL);
    // pthread_join(thread_id,NULL);
   }
}
