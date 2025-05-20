#ifndef AUX_H
#define AUX_H

#define FILENAME_MAX_SIZE 200

struct event {
	u64 type;
	u64 timestamp;
	u64 id;
	u32 pid;
	u32 tid;
	u32 arg1;
	u32 arg2;
	u32 arg3;
	u32 arg4;
	long int ret;
	char extra[FILENAME_MAX_SIZE];
};


struct process_and_syscall{
    int id;
    u64 pid_tgid;

};

struct process_fd {
	int fd;
	int pid;
	u64 timestamp;
};
struct operation_info{
	int pid;
	long unsigned int buff_addr;
};

#endif // AUX_H
