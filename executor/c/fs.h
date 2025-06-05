#ifndef __FS_H
#define __FS_H

#define FILENAME_MAX_SIZE 32
#define MAX_JUMPS 			25
#define MAX_FILE_OFFSET		(FILENAME_MAX_SIZE>>1)
#define SUB_STR_MAX			512
#define PATH_MAX	4096
#define TASK_COMM_LEN	16


struct file_info_simple {
	int size;
	char filename[FILENAME_MAX_SIZE];
}__attribute__((packed));

typedef struct file_fd_key_t {
	uint32_t dev;
    uint32_t ino;
} __attribute__((packed)) FileFDKey;

typedef struct event_path_t
{
	int etype;
	FileFDKey f_tag;
	uint64_t timestamp;
	int index;
	int n_ref;
	uint16_t cpu;
} __attribute__((packed)) EventPath;

typedef struct file_info_t {
    uint32_t n_ref;
	uint16_t file_type;
	uint32_t offset;
	uint32_t size;
	char filename[FILENAME_MAX_SIZE];
} FileInfo;

struct file_id {
	__u64 inode;
	__u32 dev;
	__u32 rdev;
	__u32 pid;
	__u32 tid;
};

struct file_stat {
	__u32 pid;
	char filename[PATH_MAX];
	char comm[TASK_COMM_LEN];
};


#endif
