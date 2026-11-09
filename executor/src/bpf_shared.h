#ifndef __BPF_SHARED_H_
#define __BPF_SHARED_H_
// Structs/enums here must stay byte-identical between the BPF programs
// (*.bpf.c / *.bpf.h) and the userspace loader (aux.c, main.c) since they're
// used as BPF map keys/values or ring buffer event payloads. Only put
// something here if a *.bpf.c file actually needs it - everything else
// belongs in aux.h.
#define STATE_PROPERTIES_COUNT 65
// fault_schedule.h includes this header to get MAX_IPS_BLOCKED, sizing
// fault.fault_details.block_ips the same as the blocked_ips BPF map value
// type (__be32[MAX_IPS_BLOCKED]) below.
#define MAX_IPS_BLOCKED 8
#define MAX_FUNCTIONS 32
#define MAX_RELEVANT_FILES 16
// Headroom above whatever a schedule statically declares is reserved for
// dynamically-injected faults (toexfi/rose_injector.py) - a schedule's own
// execution_plan.dynamic.reserved_slots picks how many of these it
// actually uses; this is just the hard upper bound the BPF-side faults
// array/maps are sized for. Previously bumped 16 -> 64 for headroom, but
// that cost is NOT just memory (~1.7KB/slot): satisfy_fault_deps()
// (state_processor.bpf.h) #pragma-unrolled a MAX_FAULTS-iteration loop at
// every fault-firing call site, so MAX_FAULTS directly inflated BPF
// verifier complexity - confirmed empirically: FAULT_COUNT=8 (5 static
// block_ips placeholders + 3 reserved_slots, sunflower's coverage-fixed
// schedule) pushed fault_inject.bpf.c's __x64_sys_write program over the
// verifier's 1M-instruction limit (-E2BIG) at MAX_FAULTS=64, aborting the
// whole run. Reverted to 16 at the time. That loop's body is now
// commented out (it was a no-op anyway - no schedule declares fault_deps
// between faults), which removes the only thing that scaled with
// MAX_FAULTS ITSELF at the verifier-complexity level, so this was bumped
// back up to 32 - every remaining MAX_FAULTS use here is just BPF map
// max_entries sizing (cheap). If satisfy_fault_deps() is ever re-enabled
// for a schedule that actually needs fault_deps, re-check this value
// against the verifier again before raising it further.
//
// IMPORTANT: this is NOT the only verifier-complexity ceiling in play.
// state_processor.bpf.h has a SEPARATE loop (~line 271, `for (int
// i=0;i<fault_count;i++)`) that calls into the large inject_fault()/
// process_counter() path once per fault a SCHEDULE actually declares
// (fault_count = static faults + reserved_slots, independent of this
// MAX_FAULTS constant). Confirmed empirically on test1 (2026-11-04),
// AFTER this MAX_FAULTS bump and with satisfy_fault_deps() disabled:
// fault_count=25 loads fine, fault_count=28 still hits the same -E2BIG
// on fault_inject.bpf.c's __x64_sys_write program. So raising MAX_FAULTS
// alone does NOT grant more headroom for reserved_slots - the schedule's
// own fault_count is the thing to watch. See
// toexfi/bug_exploration/cockroachdb/test_schedules/
// sunflower_coverage_fixed_schedule.yaml's reserved_slots comment for
// the up-to-date tested-safe value.
#define MAX_FAULTS 32
#define MAX_NODES 8
#define MAX_FAULT_DEPS 4
// Backing size for relevant_state_info/faults_specification/etc (HASH
// maps keyed per pid+condition) - bumped alongside MAX_FAULTS so dynamic
// injection has headroom to add new condition entries at runtime without
// hitting E2BIG, independent of how many fault slots are reserved.
//
// relevant_state_info now gets its entries cleaned up (rose_injector.py's
// reset_slot(), once a slot is done with its condition), so it no longer
// needs to hold EVERY distinct (origin_pid, cond_nr) key ever seen across
// a whole sweep - but a margin above what's actively in flight at any one
// moment is still needed (entries aren't cleaned up until reset_slot()
// runs, e.g. a few in flight at any point, plus the sweep's last trial's
// winning slots, which never get reset again). Bumped from 256 - cheap,
// pure map-memory sizing, no unrolled loop scales with this constant.
// faults_specification shares this constant too, but is written from the
// KERNEL side (state_processor.bpf.h's own inject_fault()) and has no
// equivalent cleanup yet - a separate, not-yet-fixed concern.
#define MAP_SIZE 1024
#define FILENAME_MAX_SIZE 64
#define MAX_JUMPS 			16
#define MAX_FILE_OFFSET		(FILENAME_MAX_SIZE>>1)
#define SUB_STR_MAX			512

struct tc_key{
    int index;
    int network_direction;
    int fault_nr;
};

struct faultstate_simple{
    //Holds the values for the conditions
    int fault_type_conditions[STATE_PROPERTIES_COUNT+MAX_FUNCTIONS];
    //Holds if the conditions are met
    int conditions_match[STATE_PROPERTIES_COUNT+MAX_FUNCTIONS];
    int dependency_fault_nrs[MAX_FAULT_DEPS];
    int dependency_satisfied[MAX_FAULT_DEPS];
};

struct simplified_fault{
    int fault_type;
    __u64 duration;
    int done;
    __u64 start_time;
    struct faultstate_simple initial;
    struct faultstate_simple end;
    int pid;
    int target;
    int target_if_index;
    int repeat;
    int occurrences;
    int return_value;
    int faults_injected_counter;
    int relevant_conditions;
    int fault_nr;
    int run;
    int quorum_size;
    int faults_done;
    // PARTIAL_WRITE_FAULT only: forwarded to rose.c's bpf_rose_arm_partial_write()
    // kfunc as its corrupt_buffer arg - see partial_write_fault in fault_schedule.h.
    int corrupt_buffer;
    __u64 timestamp;
    // "any" target support (target == -3, or dynamic reserved-slot
    // first-fire-wins groups): a real kernel-side CAS gate, replacing the
    // old userspace-only "poll every sibling slot, reset_slot() the
    // losers" race (there was a real window where two siblings' uprobe
    // conditions could both be satisfied, and BOTH independently inject,
    // before userspace noticed and disarmed the loser).
    //
    // - Static schedule_parser `target: any` faults (one fault_nr, N
    //   `begin_conditions`, see faults.py): CAS directly on THIS struct's
    //   own `claimed` field once `run >= 1` (first of the N conditions to
    //   match wins).
    // - sunflower's dynamic reserved slots (one fault_nr PER node, see
    //   rose_injector.py/coverage_fixed.py): each sibling slot's
    //   `group_leader_fault_nr` points at one designated slot in the group
    //   (often the group's own first slot); process() looks that struct up
    //   via the `faults` map (already available as `process()`'s own `map`
    //   argument - no new BPF map needed) and CASes on ITS `claimed` field
    //   instead of its own. The losing slot's `done` is set to
    //   `occurrences` so userspace's existing is_slot_free()/polling still
    //   sees the position as resolved, without a second real injection.
    //
    // __u64, not int: the BPF backend only supports a 64-bit
    // __sync_bool_compare_and_swap (confirmed empirically - a 32-bit CAS
    // crashes clang's BPF instruction selector with "unsupported atomic
    // operation, please use 64 bit version"). __sync_fetch_and_add (used
    // elsewhere on `conditions_match`, an int) is fine on 32 bits; only
    // compare-and-swap needs the wider type.
    __u64 claimed;
    int group_leader_fault_nr;
};

struct fault_key{
    int pid;
    int fault_type;
};

struct fault_description{
    int on;
    int occurences;
    int counter;
    int return_value;
    int syscall_nr;
    int fault_nr;
};

struct info_key{
    int pid;
    //type of state_condition
    int infotype;
};

struct info_state{
    int relevant_states[256];
    int current_value;
    int repeat;
};


struct  relevant_fds{
    __u64 fds[MAX_RELEVANT_FILES];
    int size;
};

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

enum fault_type{
    FORK = 1,
    WRITE = 2,
    WRITE_FILE = 8,
    READ = 3,
    READ_FILE = 9,
    NETWORK_ISOLATION = 4,
    BLOCK_IPS = 5,
    DROP_PACKETS = 6,
    CLONE = 7,
    PROCESS_KILL = 11,
    WRITE_RET = 12,
    READ_RET = 13,
    PROCESS_STOP = 14,
    OPEN = 15,
    OPEN_FILE = 20,
    MKDIR = 16,
    MKDIR_FILE = 23,
    NEWFSTATAT_FAULT = 17,
    NEWFSTATAT_FILE_FAULT = 24,
    OPENAT_FAULT = 257,
    OPENAT_RET = 21,
    OPENAT_FILE = 25,
    NEWFSTATAT_RET = 19,
    PROCESS_RESTART = 22,
    FDATASYNC_FAULT = 25,
    FDATASYNCFILE_FAULT = 26,
    FDATASYNC_RET_FAULT = 27,
    FSYNC_FAULT = 74,
    FSYNC_FILE = 740,
    PWRITE64_FAULT = 18,
    ACCEPT_FAULT = 43,
    CLOSE_FAULT = 3,
    FUTEX_FAULT = 202,
    CONNECT_FAULT = 42,
    STAT_FAULT = 49,
    LSEEK_FAULT = 50,
    UNLINK_FAULT = 51,
    SYNC_FILE_RANGE_FAULT = 52,
    BIND_FAULT = 53,
    LSTAT_FAULT = 54,
    RENAME_FAULT = 55,
    //LAZYFS
    CLEAR_CACHE = 44,
    CRASH_FS = 45,
    TORN_OP = 46,
    TORN_SEQ = 47,
    // Genuine short write via the rose.ko kprobe (rose.c's write_pre_handler) -
    // truncates the real write() count before the syscall body runs, unlike
    // WRITE/WRITE_RET which fake the return value via bpf_override_return
    // without the syscall body executing at all.
    PARTIAL_WRITE_FAULT = 56,
    // Genuine short read via rose.ko's read_pre_handler - read()-side mirror
    // of PARTIAL_WRITE_FAULT (truncates count, buffer untouched).
    PARTIAL_READ_FAULT = 57,
    // Silently corrupts part of a read()'s *successfully returned* bytes via
    // rose.ko's torn_read_krp kretprobe, after the real read completes - the
    // read()-side mirror of a real disk failure (data silently wrong despite
    // reported success), as opposed to PARTIAL_READ_FAULT's truncated count.
    TORN_READ_FAULT = 58,
    // New syscall faults - block reserved for these: fault_type 100-125,
    // see skills/add_syscall.md.
    CLONE_FAULT = 100,
    DUP_FAULT = 101,
    EPOLL_CREATE1_FAULT = 102,
    EPOLL_CTL_FAULT = 103,
    EPOLL_PWAIT_FAULT = 104,
    EVENTFD2_FAULT = 105,
    FCNTL_FAULT = 106,
    FLOCK_FAULT = 107,
    FSTAT_FAULT = 108,
    FTRUNCATE_FAULT = 109,
    GETDENTS64_FAULT = 110,
    GETPEERNAME_FAULT = 111,
    GETSOCKNAME_FAULT = 112,
    IOCTL_FAULT = 113,
    LISTEN_FAULT = 114,
    MADVISE_FAULT = 115,
    MKDIRAT_FAULT = 116,
    MMAP_FAULT = 117,
    MPROTECT_FAULT = 118,
    PIPE_FAULT = 119,
    PRCTL_FAULT = 120,
    SCHED_GETAFFINITY_FAULT = 121,
    SOCKET_FAULT = 122,
    STATFS_FAULT = 123,
    TGKILL_FAULT = 124,
    UNLINKAT_FAULT = 125,
    MSYNC_FAULT = 126,
    RENAMEAT_FAULT = 127,
    EXECVE_FAULT = 128,
    ACCEPT4_FAULT = 129,
    TEMP_EMPTY = 999
};

//Positions of array which correspond to a certain counter
enum stateinfo{
    PROCESSES_OPENED = 0,
    PROCESSES_CLOSED = 1,
    FILES_OPENED = 2,
    FILES_CLOSED = 3,
    FILES_OPENED_ANY = 4,
    FILES_CLOSED_ANY = 5,
    WRITES = 6,
    READS = 7,
    WRITE_FILE_STATE = 8,
    READ_FILE_STATE = 9,
    CALLCOUNT = 10,
    THREADS_CREATED = 11,
    OPENS = 12,
    DIRCREATED =123,
    NEWFSTATAT_STATE = 14,
    OPENNAT_STATE = 15,
    NEWFSTATAT_FILE_STATE = 16,
    OPENAT_SPECIFIC = 17,
    TIME_STATE = 18,
    FDATASYNC_STATE = 19,
    FDATASYNC_FILE_STATE = 20,
    FSYNC_STATE = 21,
    FSYNCFILE_STATE= 22,
    PWRITE64_STATE = 23,
    ACCEPT_STATE = 24,
    CLOSE_STATE = 25,
    FUTEX_STATE = 26,
    CONNECT_STATE = 27,
    STAT_STATE = 28,
    LSEEK_STATE = 29,
    UNLINK_STATE = 30,
    SYNC_FILE_RANGE_STATE = 31,
    BIND_STATE = 32,
    LSTAT_STATE = 33,
    RENAME_STATE = 34,
    // New syscall faults - block reserved for these: stateinfo 35-60,
    // see skills/add_syscall.md.
    CLONE_STATE = 35,
    DUP_STATE = 36,
    EPOLL_CREATE1_STATE = 37,
    EPOLL_CTL_STATE = 38,
    EPOLL_PWAIT_STATE = 39,
    EVENTFD2_STATE = 40,
    FCNTL_STATE = 41,
    FLOCK_STATE = 42,
    FSTAT_STATE = 43,
    FTRUNCATE_STATE = 44,
    GETDENTS64_STATE = 45,
    GETPEERNAME_STATE = 46,
    GETSOCKNAME_STATE = 47,
    IOCTL_STATE = 48,
    LISTEN_STATE = 49,
    MADVISE_STATE = 50,
    MKDIRAT_STATE = 51,
    MMAP_STATE = 52,
    MPROTECT_STATE = 53,
    PIPE_STATE = 54,
    PRCTL_STATE = 55,
    SCHED_GETAFFINITY_STATE = 56,
    SOCKET_STATE = 57,
    STATFS_STATE = 58,
    TGKILL_STATE = 59,
    UNLINKAT_STATE = 60,
    MSYNC_STATE = 61,
    RENAMEAT_STATE = 62,
    EXECVE_STATE = 63,
    ACCEPT4_STATE = 64
};


enum generic{
    ANY_PID = 411,
    LEADER_CHANGE = 13
};

enum condition_mode {
    NORMAL   = 0,
    FAULT_DEP = 1,
    TIME_DEP  = 2,
};

struct event {
	int type;
	int pid;
	int ppid;
    int fault_nr;
	unsigned exit_code;
	unsigned long long duration_ns;
    __u64 state_condition;
    int syscall_nr;
};

struct sys_info {
	int fd;
	int general_syscall_code;
	int file_specific_code;
	int general_fault_code;
	int file_specific_fault_code;
	int fault_count;
	int mode;
};

#endif /* __BPF_SHARED_H_ */
