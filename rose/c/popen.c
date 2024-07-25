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

static int ready = 0;
void sig_handler(int signum){
    ready = 1;
}

FILE * custom_popen(char* command, char **args, char **env,char type, pid_t* pid)
{   

    pid_t child_pid;
    int fd[2];
    pipe(fd);
    if((child_pid = fork()) == -1)
    {
        perror("fork \n");
        exit(1);
    }
    /* child process */
    if (child_pid == 0)
    {
        if (type == 'r')
        {
            close(fd[0]);    //Close the READ end of the pipe since the child's fd is write-only
            dup2(fd[1], 1); //Redirect stdout to pipe
        }
        else
        {
            close(fd[1]);    //Close the WRITE end of the pipe since the child's fd is read-only
            dup2(fd[0], 0);   //Redirect stdin to pipe
        }

        setpgid(child_pid, child_pid); //Needed so negative PIDs can kill children of /bin/sh

        signal(SIGUSR1,sig_handler); // Register signal handler

        while(true){
            if(ready){
                //printf("Received signal \n");
                break;
            }
            sleep(0.000001);

        }
        //turn off signal
        int err = execvpe(command,args,env);
        printf("Err in execv is %d and errno is %d \n",err,errno);
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
    //printf("PID IS %d \n",child_pid);   
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