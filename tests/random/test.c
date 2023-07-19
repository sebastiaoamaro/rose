#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

static int count = 0;
int uprobing(char *string){
    printf("Uprobing count %d \n",count);
    count++;
    sleep(1);
}

int main() {
   // printf() displays the string inside quotation
   printf("Pid %d \n",getpid());
   while(1){

    // char string[32] = "String";
    // FILE *fptr;
    // fptr = fopen("test.txt","a");
    // fprintf(fptr,"%s\n",string);
    // fclose(fptr);
    //sleep(2);
    pthread_t thread_id;
    pthread_create(&thread_id,NULL,uprobing,NULL);
    pthread_join(thread_id,NULL);
   }
}
