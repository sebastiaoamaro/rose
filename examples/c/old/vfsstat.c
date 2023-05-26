// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on vfsstat(8) from BCC by Brendan Gregg
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "vfsstat.h"
#include "vfsstat.skel.h"
//#include "trace_helpers.h"

// const char *argp_program_version = "vfsstat 0.1";
// const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
// static const char argp_program_doc[] =
// 	"\nvfsstat: Count some VFS calls\n"
// 	"\n"
// 	"EXAMPLES:\n"
// 	"    vfsstat      # interval one second\n"
// 	"    vfsstat 5 3  # interval five seconds, three output lines\n";
// static char args_doc[] = "[interval [count]]";

// static const struct argp_option opts[] = {
// 	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
// 	{ "pid", 'p', "PID", 0, "Process PID to trace" },
// 	{},
// };

static struct env {
	bool verbose;
	int pid;
	int count;
	int interval;
} env = {
	.interval = 1,	/* once a second */
};

static int get_int(const char *arg, int *ret, int min, int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(arg, &end, 10);
	if (errno) {
		fprintf(stderr, "strtol: %s\n", arg);
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long interval;
	long count;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = get_int(arg, &env.pid, 1, INT_MAX);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			errno = 0;
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0 || interval > INT_MAX) {
				fprintf(stderr, "invalid interval: %s\n", arg);
				argp_usage(state);
			}
			env.interval = interval;
			break;
		case 1:
			errno = 0;
			count = strtol(arg, NULL, 10);
			if (errno || count < 0 || count > INT_MAX) {
				fprintf(stderr, "invalid count: %s\n", arg);
				argp_usage(state);
			}
			env.count = count;
			break;
		default:
			argp_usage(state);
			break;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *strftime_now(char *s, size_t max, const char *format)
{
	struct tm *tm;
	time_t t;

	t = time(NULL);
	tm = localtime(&t);
	if (tm == NULL) {
		fprintf(stderr, "localtime: %s\n", strerror(errno));
		return "<failed>";
	}
	if (strftime(s, max, format, tm) == 0) {
		fprintf(stderr, "strftime error\n");
		return "<failed>";
	}
	return s;
}

static const char *stat_types_names[] = {
	[S_READ] = "READ",
	[S_WRITE] = "WRITE",
	[S_FSYNC] = "FSYNC",
	[S_OPEN] = "OPEN",
	[S_CREATE] = "CREATE",
};

static void print_header(void)
{
	//printf("%-8s %-6s %-6s %-6s \n", "TIME", "PID", "SIZE", "TYPE");
	// printf("%-8s ", "TIME");
	// for (int i = 0; i < S_MAXSTAT; i++)
	// 	printf(" %6s/s", stat_types_names[i]);
	// printf("\n");
}


static void print_and_reset_stats(__u64 stats[S_MAXSTAT])
{
	char s[16];
	__u64 val;

	printf("%-8s: ", strftime_now(s, sizeof(s), "%H:%M:%S"));
	for (int i = 0; i < S_MAXSTAT; i++) {
		val = __atomic_exchange_n(&stats[i], 0, __ATOMIC_RELAXED);
		printf(" %8llu", val / env.interval);
	}
	printf("\n");
}

static char *array[NUMBER_STRINGS];

static int count = 0;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event_vfsstat *e = data;
	//char s[16];
	char *name;
	int i;
	for(i=0;i<count;i++){
		
		if (strcmp(array[i],e->name) == 0){
			return 0;
		}
	}
	int l;
	char *x;
	l = strlen(e->name);
	x = (char *)malloc(l+1);
	strcpy(x,e->name);
	array[count] = x;
    //if(env.verbose)
	// printf(" e->name %s in pos %d\n",e->name,count);
	// printf(" array[count] %s in pos %d \n",array[count],count);
	//printf("%s \n",e->name);
	count++;
	//printf("%-8s %-6d %-6d %-6s \n", strftime_now(s, sizeof(s), "%H:%M:%S"), e->pid, e->size, stat_types_names[e->type]);
	return 0;
}

static void print_events(int ring_map_fd)
{
	struct ring_buffer *rb = NULL;
	int err;

	/* Set up ring buffer polling */
	rb = ring_buffer__new(ring_map_fd, handle_event, NULL, NULL);
	if (!rb) {
		rb = NULL;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */

	while (true) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			goto cleanup;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	ring_buffer__free(rb);
}

void printMapInfo(int fd)
{
	struct bpf_map_info map_info = {};
	uint32_t map_info_len = sizeof(struct bpf_map_info);

	bpf_obj_get_info_by_fd(fd, &map_info, &map_info_len);

	printf("\n[MAP] Pinned bpf-map successfuly\n");
	char str[80];
	strcpy(str, "/sys/fs/bpf/");
	strcat(str, map_info.name);
	printf("[MAP] path: %s\n", str);
	printf("[MAP] fd:   %d\n", fd);
	printf("[MAP] name: %s\n", map_info.name);
	printf("[MAP] id:   %d\n", map_info.id);
}

int pinMaps(struct vfsstat_bpf *obj) 	// int fd = bpf_map_get_fd_by_id(44);
{
	int err;

	err = bpf_map__unpin(obj->maps.read_map, "/sys/fs/bpf/read_map");
	if(err) {
		if(env.verbose) {
			printf("[ERROR] libbpf unpin API: %d\n", err);
		}
	}
	
	err = bpf_map__pin(obj->maps.read_map, "/sys/fs/bpf/read_map");
	//err = bpf_obj_pin(fd, "/sys/fs/bpf/ss_sendmsg");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return err;
	}

	err = bpf_map__unpin(obj->maps.write_map, "/sys/fs/bpf/write_map");
	if(err) {
		if(env.verbose) {
			printf("[ERROR] libbpf unpin API: %d\n", err);
		}
	}
	
	err = bpf_map__pin(obj->maps.write_map, "/sys/fs/bpf/write_map");
	//err = bpf_obj_pin(fd, "/sys/fs/bpf/ipv6_send_bytes");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return err;
	}

	err = bpf_map__unpin(obj->maps.fsync_map, "/sys/fs/bpf/fsync_map");
	if(err) {
		if(env.verbose) {
			printf("[ERROR] libbpf unpin API: %d\n", err);
		}
	}
	
	err = bpf_map__pin(obj->maps.fsync_map, "/sys/fs/bpf/fsync_map");
	//err = bpf_obj_pin(fd, "/sys/fs/bpf/ss_sendmsg");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return err;
	}

	err = bpf_map__unpin(obj->maps.open_map, "/sys/fs/bpf/open_map");
	if(err) {
		if(env.verbose) {
			printf("[ERROR] libbpf unpin API: %d\n", err);
		}
	}
	
	err = bpf_map__pin(obj->maps.open_map, "/sys/fs/bpf/open_map");
	//err = bpf_obj_pin(fd, "/sys/fs/bpf/ipv6_send_bytes");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return err;
	}

	err = bpf_map__unpin(obj->maps.create_map, "/sys/fs/bpf/create_map");
	if(err) {
		if(env.verbose) {
			printf("[ERROR] libbpf unpin API: %d\n", err);
		}
	}
	
	err = bpf_map__pin(obj->maps.create_map, "/sys/fs/bpf/create_map");
	//err = bpf_obj_pin(fd, "/sys/fs/bpf/ss_sendmsg");
	if(err) {
		printf("[ERROR] libbpf pin API: %d\n", err);
		return err;
	}

	//if(env.verbose) {
	printf("Successfully pinned all maps\n");
	printMapInfo(bpf_map__fd(obj->maps.read_map));
	printMapInfo(bpf_map__fd(obj->maps.write_map));
	printMapInfo(bpf_map__fd(obj->maps.fsync_map));
	printMapInfo(bpf_map__fd(obj->maps.open_map));
	printMapInfo(bpf_map__fd(obj->maps.create_map));
	//}

	return 0;
}

int vfsstat()
{
	// static const struct argp argp = {
	// 	.options = opts,
	// 	.parser = parse_arg,
	// 	.doc = argp_program_doc,
	// 	.args_doc = args_doc,
	// };
	struct vfsstat_bpf *obj;
	int err;

	// err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	// if (err)
	// 	return err;

	libbpf_set_print(libbpf_print_fn);

	// err = bump_memlock_rlimit();
	// if (err) {
	// 	fprintf(stderr, "failed to increase rlimit: %s\n",
	// 			strerror(errno));
	// 	return 1;
	// }

	/* Load and verify BPF application */
	obj = vfsstat_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	obj->rodata->filter_pid = env.pid;

	/* Load & verify BPF programs */
	err = vfsstat_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = vfsstat_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n",
				strerror(-err));
		goto cleanup;
	}

	pinMaps(obj);
	print_header();
	print_events(bpf_map__fd(obj->maps.rb));
	do {
		sleep(env.interval);
		print_and_reset_stats(obj->bss->stats);
	} while (!env.count || --env.count);

cleanup:
	vfsstat_bpf__destroy(obj);

	return err != 0;
}