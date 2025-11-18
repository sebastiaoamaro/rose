#ifndef __FS_H
#define __FS_H

#define FILENAME_MAX_SIZE 64
#define MAX_JUMPS 			16
#define MAX_FILE_OFFSET		(FILENAME_MAX_SIZE>>1)
#define SUB_STR_MAX			512
#define PATH_MAX	4096
#define TASK_COMM_LEN	16


struct file_info_simple {
	int size;
	char filename[32];
}__attribute__((packed));

typedef struct file_fd_key_t {
	uint32_t dev;
    uint32_t ino;
} __attribute__((packed)) FileFDKey;


typedef struct file_info_t {
	uint32_t offset;
	uint32_t size;
	char filename[FILENAME_MAX_SIZE];
} FileInfo;



#endif
