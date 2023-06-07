#include <stdio.h>
#include <unistd.h>
int main() {
   // printf() displays the string inside quotation
   while(1){
    uprobing();
   }
}

int uprobing(){
    printf("Uprobing pid %d \n",getpid());
    sleep(5);
}