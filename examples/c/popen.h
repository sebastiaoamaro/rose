#ifndef __POPEN_H_
#define __POPEN_H_
FILE * custom_popen(char* command,char** args, char type, pid_t* pid);
int custom_pclose(FILE*,int);
#endif /* __POPEN_H */