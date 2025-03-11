#ifndef AUX_H
#define AUX_H

#define FILENAME_MAX_SIZE 256

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

#endif // AUX_H
