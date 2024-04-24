#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>

int fdatasync(int fildes) {

    int *(*original_fdatasync)(int fildes);
    original_fdatasync = dlsym(RTLD_NEXT, "fdatasync");

    int result = original_fdatasync(fildes);

    printf("Result is %d errno is %d\n",result,errno);

    if(result==-51139){
        sleep(60);
    }
    
    return 0;
}