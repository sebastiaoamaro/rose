#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include "aux.h"

static int ready = 0;
void sig_handler(int signum){
    ready = 1;
}

FILE * custom_popen(char* command, char **args, char **env,char type, pid_t* pid, int container_process)
{
    pid_t child_pid;
    int fd[2];
    pipe(fd);
    if((child_pid = fork()) == -1)
    {
        perror("fork \n");
        exit(1);
    }
    if (child_pid == 0)
    {
        if (type == 'r')
        {
            close(fd[0]);
            dup2(fd[1], 1);
        }
        else
        {
            close(fd[1]);
            dup2(fd[0], 0);
        }

        setpgid(child_pid, child_pid); //Needed so negative PIDs can kill children of /bin/sh

        //If it is not a container process, wait for the signal to start
        if (!container_process){
            signal(SIGUSR1,sig_handler);
            while(true){
                if(ready){
                    break;
                }
                sleep_for_ms(1);
            }
        }
        int err = execvp(command,args);
        if (err < 0)
            printf("COMMAND:%s, Err in execvp: %s (errno=%d)\n", command, strerror(errno), errno);
        exit(0);
    }
    else
    {
        if (type == 'r')
        {
            close(fd[1]); //Close the WRITE end of the pipe since parent's fd is read-only
        }
        else
        {
            close(fd[0]); //Close the READ end of the pipe since parent's fd is write-only
        }

    }
    *pid = child_pid;
    if (type == 'r')
    {
        return fdopen(fd[0], "r");
    }

    return fdopen(fd[1], "w");
}

int custom_pclose(FILE * fp, pid_t pid)
{
    int stat;

    fclose(fp);
    while (waitpid(pid, &stat, 0) == -1)
    {
        if (errno != EINTR)
        {
            stat = -1;
            break;
        }
    }

    return stat;
}
