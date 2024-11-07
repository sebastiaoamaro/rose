use anyhow::{bail,Result};
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use procfs::process::Process;
use procfs::process::Stat;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;
use std::str;
use std::sync::mpsc;
use std::thread;
use std::time;

#[repr(C)]
pub struct syscall_op {
    id: i32,
    pid_tgid: u64,
    ret: i32,
    time: u64,
}
#[repr(C)]
pub struct io_op {
    tag: i32,
    pid: i32,
    size: i32,
    buffer: [u8; 64],
}
#[repr(C)]
pub struct event{
    pub event_type:u64,
    pub timestamp:u64,
    pub id:u64,
	pub pid:u32,
    pub tid:u32,
    pub ret:i32,
    pub arg1:u32,
    pub arg2:u32,
    pub arg3:u32,
    pub arg4:u32
}

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn read_numbers_from_file(filename: &str) -> io::Result<Vec<i32>> {
    let path = Path::new(filename);
    let file = File::open(&path)?;
    let reader = io::BufReader::new(file);

    let mut numbers = Vec::new();

    for line in reader.lines() {
        let line = line?;
        match line.trim().parse::<i32>() {
            Ok(num) => numbers.push(num),
            Err(e) => eprintln!("Error parsing number '{}': {}", line, e),
        }
    }

    Ok(numbers)
}

pub fn u32_to_u8_array_little_endian(value: i32) -> [u8; 4] {
    [
        value as u8,
        (value >> 8) as u8,
        (value >> 16) as u8,
        (value >> 24) as u8,
    ]
}

pub fn u64_to_u8_array_little_endian(value: u64) -> [u8; 8] {
    [
        value as u8,
        (value >> 8) as u8,
        (value >> 16) as u8,
        (value >> 24) as u8,
        (value >> 32) as u8,
        (value >> 40) as u8,
        (value >> 48) as u8,
        (value >> 56) as u8,
    ]
}

pub fn vec_to_i32(bytes: Vec<u8>) -> i32 {
    // Ensure the Vec<u8> has exactly 4 bytes
    let byte_array: [u8; 4] = bytes.try_into().expect("Vec<u8> must have exactly 4 elements");

    // Convert the [u8; 4] array into an i32
    i32::from_le_bytes(byte_array) // Converts assuming little-endian byte order
}

pub fn write_to_file(filename: String, content: String) -> std::io::Result<()> {
    // Open a file in write mode, creating it if it doesn't exist
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true) // Create the file if it doesn't exist
        .open(filename)?;

    // Write the content to the file
    file.write_all(content.as_bytes())?;

    // Flush the buffer to ensure all data is written to the file
    file.flush()?;

    Ok(())
}

pub fn collect_trace(syscall_map: &libbpf_rs::Map, io_ops_map: &libbpf_rs::Map, node_count: i32) {
    print!("Collecing trace \n");
    let keys = syscall_map.keys();

    for key in keys {
        let result = syscall_map
            .lookup(&key, MapFlags::ANY)
            .expect("This key is not in syscall_map");

        let sys_op_raw = result.unwrap().clone();

        //println!("Result is {:?}",sys_op);

        unsafe {
            let sys_op: *const syscall_op = sys_op_raw.as_ptr() as *const syscall_op;
            let readable_sys_op: &syscall_op = &*sys_op;

            let pid = (readable_sys_op.pid_tgid >> 32) as u32;

            if readable_sys_op.id == 0 {
                continue;
            }

            //println!("id:{} ret:{} pid_tgid:{} time:{}", readable_sys_op.id, readable_sys_op.ret,pid,readable_sys_op.time);
        }
    }

    let keys = io_ops_map.keys();

    let mut total = 0;
    let mut count = 0;
    for key in keys {
        let result = io_ops_map.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let io_op_raw = result.unwrap().clone();

                unsafe {
                    let io_op: *const io_op = io_op_raw.as_ptr() as *const io_op;
                    let readable_io_op: &io_op = &*io_op;

                    if readable_io_op.tag == 0 {
                        continue;
                    }
                    //let text = buffer_to_string(&readable_io_op.buffer);

                    //println!("tag:{} pid:{} buffer:{:?}", readable_io_op.tag, readable_io_op.pid,text);
                    if readable_io_op.tag == 2 {
                        total += readable_io_op.size;
                    }
                }
                count += 1;
            }
            Err(e) => {
                println!("Err: {:?}", e);
            }
        }
    }

    let average = total / count;
    match write_to_file(
        format!("/tmp/read_average{}", node_count),
        format!("Average:{} \n", average.to_string()),
    ) {
        Ok(_) => println!("File successfully written."),
        Err(e) => eprintln!("Error writing file: {}", e),
    }
}

pub fn buffer_to_string(buffer: &[u8]) -> String {
    let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
    str::from_utf8(&buffer[..len]).unwrap_or("").to_string()
}

pub fn get_overlay2_location(container_name: &str) -> Result<String, io::Error> {
    // Construct the command
    let command = format!(
        "docker container inspect {} | jq -r '.[0].GraphDriver.Data.MergedDir'",
        container_name
    );

    // Execute the command
    let output = Command::new("sh").arg("-c").arg(&command).output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to execute command",
        ));
    }

    // Convert the command output to a String
    let mut response = String::from_utf8_lossy(&output.stdout).to_string();

    // Remove the trailing newline character
    if let Some(pos) = response.rfind('\n') {
        response.truncate(pos);
    }

    Ok(response)
}

pub fn read_names_from_file(filename: &str) -> io::Result<Vec<String>> {
    // Open the file
    let file = File::open(filename)?;
    // Create a buffered reader
    let reader = BufReader::new(file);

    // Collect lines into a vector
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    Ok(lines)
}

pub fn remove_duplicates(vec: Vec<u64>) -> Vec<u64> {
    let mut seen = HashSet::new();
    vec.into_iter()
        .filter(|&x| seen.insert(x))
        .collect()                   
}

pub fn collect_functions_called_array(called_functions: &libbpf_rs::Map,functions:Vec<String>,hashmap_pid_to_node:HashMap<i32,String>){
    
   let keys = called_functions.keys();
   println!("Collecting events \n ");
   //Use later
   let mut history: Vec<&event> = vec![];

   for key in keys {
       let result = called_functions.lookup(&key, MapFlags::ANY);

       match result {
           Ok(result) => {
               let event = result.unwrap().clone();

               unsafe {
                    let event: *const event = event.as_ptr() as *const event;
                    let event: &event = &*event;

                    if event.pid == 0{
                        continue;
                    }
                    
                    history.push(event);

                    if event.event_type == 1{
                        //println!("Added sys_enter with ret {}",event.ret);
                        let pid = event.pid as i32;
                        let event_name = get_syscall_name(event.id);
                        let node_name = hashmap_pid_to_node.get(&pid).expect(&format!("Failed to node-name for pid {}",event.pid));
                        write_event_to_history(event, node_name, &event_name);
                    }
                    if event.event_type == 2{
                        //println!("Added sys_exit with ret {}",event.ret);
                        let pid = event.pid as i32;
                        let event_name = get_syscall_name(event.id);
                        let node_name = hashmap_pid_to_node.get(&pid).expect(&format!("Failed to node-name for pid {}",event.pid));
                        write_event_to_history(event, node_name, &event_name);
                    }
                    if event.event_type == 3{
                        let pid = event.pid as i32;
                        let node_name = hashmap_pid_to_node.get(&pid).expect(&format!("Failed to node-name for pid {}",event.pid));
                        let event_name = functions.get(event.id as usize).expect(&format!("Failed to get function name for id {}",event.id));
                        write_event_to_history(event, node_name, event_name);
                    }
                    if event.event_type == 3{
                        write_event_to_history(event, &"any".to_string(), &"network_delay".to_string());
                    }

                    
                   
               }
           }
           Err(e) => {
               println!("Err: {:?}", e);
           }
       }
   }
}

//Used for stats and to remove useless probes
pub fn process_uprobes_array_map(uprobes_array:&libbpf_rs::Map){

    let keys = uprobes_array.keys();

    let mut uprobes_counters:Vec<i32> = vec![0;512];

    for key in keys {
        let result = uprobes_array.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {

                let cookie = vec_to_i32(key);

                let value_vec = result.unwrap().clone();

                let value = vec_to_i32(value_vec);
            
                uprobes_counters[cookie as usize] = value;

            }
            Err(e) => {
                println!("Err: {:?}", e);
            }
        }
    }

    File::create("/tmp/uprobe_stats.txt").expect("Failed to create file");

    for (index, value) in uprobes_counters.iter().enumerate() {
 
        if *value > 0{
            write_to_file("/tmp/uprobe_stats.txt".to_string(), format!("{},{}\n",index,value)).expect("Failed to write to stats file");
        }
    }

}

pub fn monitor_pid(pid: i32,stop_signal: mpsc::Receiver<()>) -> Result<(), Box<dyn std::error::Error>> {

    let sleep_duration = time::Duration::from_millis(1000);
    let mut events_process_pause = vec![];
    // Try to open the process with the specified PID
    let process = Process::new(pid)?;
    let mut last_state = process.stat().unwrap().state().unwrap();
    loop {

        if stop_signal.try_recv().is_ok() {
            println!("Stopping monitoring for PID {}", pid);
            break;
        }

        // Fetch process information
        let p_info = process.stat();

        match p_info {
            Ok(p_info) => {
                let state: procfs::process::ProcState = p_info.state().unwrap();

                let pid = p_info.pid;
                let timestamp = std::time::Duration::from(nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?).as_nanos();
                //
                if state != last_state {
                    let event = event{
                        event_type: 5,
                        id: 0,
                        pid: pid as u32,
                        tid: 0,
                        timestamp: timestamp as u64,
                        ret: 0,
                        arg1: state as u32,
                        arg2: 0,
                        arg3: 0,
                        arg4: 0,
                    };

                    events_process_pause.push(event);
                    last_state = state;
                }

                thread::sleep(sleep_duration);
            }
            Err(e) => {
                continue;
            }
        }
    }

    for event in events_process_pause {
        let event_name = "process_change".to_string();
        let node_name = "any".to_string();
        write_event_to_history(&event, &node_name, &event_name);
    }

    Ok(())
}


// fn calculate_cpu_usage(process: &Process) -> Result<f64, Box<dyn std::error::Error>> {
//     // Simplified CPU calculation (requires /proc/stat for a fully accurate measure)
//     let sleep_duration = time::Duration::from_secs(1);

//     let stat_1 = process.stat();

//     if stat_1.is_err() {
//         return Ok(0.0);
//     }
//     let total_time_1 = (stat_1.as_ref().unwrap().utime + stat_1.unwrap().stime) as f64;

//     thread::sleep(sleep_duration);

//     let stat_2 = process.stat();
    
//     if stat_2.is_err() {
//         return Ok(0.0);
//     }

//     let total_time_2 = (stat_2.as_ref().unwrap().utime + stat_2.unwrap().stime) as f64;

//     let total_time_diff = total_time_2 - total_time_1;
    
//     let cpu_usage = (total_time_diff / procfs::ticks_per_second() as f64)*100.0;

//     Ok(cpu_usage)
// }


pub fn write_event_to_history(event:&event,node_name:&String,event_name:&String){

    write_to_file("/tmp/history.txt".to_string(),format!("Node:{},Pid:{},Tid:{},event_name:{},ret:{},time:{},arg1:{},arg2:{},arg3:{},arg4:{}\n",
    node_name,event.pid,event.tid,event_name,event.ret,event.timestamp,event.arg1,event.arg2,event.arg3,event.arg4)).expect("Failed to dump history");
}

pub fn get_syscall_name(syscall_id: u64) -> String {
    match syscall_id {
        0 => String::from("read"),
        1 => String::from("write"),
        2 => String::from("open"),
        3 => String::from("close"),
        4 => String::from("stat"),
        5 => String::from("fstat"),
        6 => String::from("lstat"),
        7 => String::from("poll"),
        8 => String::from("lseek"),
        9 => String::from("mmap"),
        10 => String::from("mprotect"),
        11 => String::from("munmap"),
        12 => String::from("brk"),
        13 => String::from("rt_sigaction"),
        14 => String::from("rt_sigprocmask"),
        15 => String::from("rt_sigreturn"),
        16 => String::from("ioctl"),
        17 => String::from("pread64"),
        18 => String::from("pwrite64"),
        19 => String::from("readv"),
        20 => String::from("writev"),
        21 => String::from("access"),
        22 => String::from("pipe"),
        23 => String::from("select"),
        24 => String::from("sched_yield"),
        25 => String::from("mremap"),
        26 => String::from("msync"),
        27 => String::from("mincore"),
        28 => String::from("madvise"),
        29 => String::from("shmget"),
        30 => String::from("shmat"),
        31 => String::from("shmctl"),
        32 => String::from("dup"),
        33 => String::from("dup2"),
        34 => String::from("pause"),
        35 => String::from("nanosleep"),
        36 => String::from("getitimer"),
        37 => String::from("alarm"),
        38 => String::from("setitimer"),
        39 => String::from("getpid"),
        40 => String::from("sendfile"),
        41 => String::from("socket"),
        42 => String::from("connect"),
        43 => String::from("accept"),
        44 => String::from("sendto"),
        45 => String::from("recvfrom"),
        46 => String::from("sendmsg"),
        47 => String::from("recvmsg"),
        48 => String::from("shutdown"),
        49 => String::from("bind"),
        50 => String::from("listen"),
        51 => String::from("getsockname"),
        52 => String::from("getpeername"),
        53 => String::from("socketpair"),
        54 => String::from("setsockopt"),
        55 => String::from("getsockopt"),
        56 => String::from("clone"),
        57 => String::from("fork"),
        58 => String::from("vfork"),
        59 => String::from("execve"),
        60 => String::from("exit"),
        61 => String::from("wait4"),
        62 => String::from("kill"),
        63 => String::from("uname"),
        64 => String::from("semget"),
        65 => String::from("semop"),
        66 => String::from("semctl"),
        67 => String::from("shmdt"),
        68 => String::from("msgget"),
        69 => String::from("msgsnd"),
        70 => String::from("msgrcv"),
        71 => String::from("msgctl"),
        72 => String::from("fcntl"),
        73 => String::from("flock"),
        74 => String::from("fsync"),
        75 => String::from("fdatasync"),
        76 => String::from("truncate"),
        77 => String::from("ftruncate"),
        78 => String::from("getdents"),
        79 => String::from("getcwd"),
        80 => String::from("chdir"),
        81 => String::from("fchdir"),
        82 => String::from("rename"),
        83 => String::from("mkdir"),
        84 => String::from("rmdir"),
        85 => String::from("creat"),
        86 => String::from("link"),
        87 => String::from("unlink"),
        88 => String::from("symlink"),
        89 => String::from("readlink"),
        90 => String::from("chmod"),
        91 => String::from("fchmod"),
        92 => String::from("chown"),
        93 => String::from("fchown"),
        94 => String::from("lchown"),
        95 => String::from("umask"),
        96 => String::from("gettimeofday"),
        97 => String::from("getrlimit"),
        98 => String::from("getrusage"),
        99 => String::from("sysinfo"),
        100 => String::from("times"),
        101 => String::from("ptrace"),
        102 => String::from("getuid"),
        103 => String::from("syslog"),
        104 => String::from("getgid"),
        105 => String::from("setuid"),
        106 => String::from("setgid"),
        107 => String::from("geteuid"),
        108 => String::from("getegid"),
        109 => String::from("setpgid"),
        110 => String::from("getppid"),
        111 => String::from("getpgrp"),
        112 => String::from("setsid"),
        113 => String::from("setreuid"),
        114 => String::from("setregid"),
        115 => String::from("getgroups"),
        116 => String::from("setgroups"),
        117 => String::from("setresuid"),
        118 => String::from("getresuid"),
        119 => String::from("setresgid"),
        120 => String::from("getresgid"),
        121 => String::from("getpgid"),
        122 => String::from("setfsuid"),
        123 => String::from("setfsgid"),
        124 => String::from("getsid"),
        125 => String::from("capget"),
        126 => String::from("capset"),
        127 => String::from("rt_sigpending"),
        128 => String::from("rt_sigtimedwait"),
        129 => String::from("rt_sigqueueinfo"),
        130 => String::from("rt_sigsuspend"),
        131 => String::from("sigaltstack"),
        132 => String::from("utime"),
        133 => String::from("mknod"),
        134 => String::from("uselib"),
        135 => String::from("personality"),
        136 => String::from("ustat"),
        137 => String::from("statfs"),
        138 => String::from("fstatfs"),
        139 => String::from("sysfs"),
        140 => String::from("getpriority"),
        141 => String::from("setpriority"),
        142 => String::from("sched_setparam"),
        143 => String::from("sched_getparam"),
        144 => String::from("sched_setscheduler"),
        145 => String::from("sched_getscheduler"),
        146 => String::from("sched_get_priority_max"),
        147 => String::from("sched_get_priority_min"),
        148 => String::from("sched_rr_get_interval"),
        149 => String::from("mlock"),
        150 => String::from("munlock"),
        151 => String::from("mlockall"),
        152 => String::from("munlockall"),
        153 => String::from("vhangup"),
        154 => String::from("modify_ldt"),
        155 => String::from("pivot_root"),
        156 => String::from("_sysctl"),
        157 => String::from("prctl"),
        158 => String::from("arch_prctl"),
        159 => String::from("adjtimex"),
        160 => String::from("setrlimit"),
        161 => String::from("chroot"),
        162 => String::from("sync"),
        163 => String::from("acct"),
        164 => String::from("settimeofday"),
        165 => String::from("mount"),
        166 => String::from("umount2"),
        167 => String::from("swapon"),
        168 => String::from("swapoff"),
        169 => String::from("reboot"),
        170 => String::from("sethostname"),
        171 => String::from("setdomainname"),
        172 => String::from("iopl"),
        173 => String::from("ioperm"),
        174 => String::from("create_module"),
        175 => String::from("init_module"),
        176 => String::from("delete_module"),
        177 => String::from("get_kernel_syms"),
        178 => String::from("query_module"),
        179 => String::from("quotactl"),
        180 => String::from("nfsservctl"),
        181 => String::from("getpmsg"),
        182 => String::from("putpmsg"),
        183 => String::from("afs_syscall"),
        184 => String::from("tuxcall"),
        185 => String::from("security"),
        186 => String::from("gettid"),
        187 => String::from("readahead"),
        188 => String::from("setxattr"),
        189 => String::from("lsetxattr"),
        190 => String::from("fsetxattr"),
        191 => String::from("getxattr"),
        192 => String::from("lgetxattr"),
        193 => String::from("fgetxattr"),
        194 => String::from("listxattr"),
        195 => String::from("llistxattr"),
        196 => String::from("flistxattr"),
        197 => String::from("removexattr"),
        198 => String::from("lremovexattr"),
        199 => String::from("fremovexattr"),
        200 => String::from("tkill"),
        201 => String::from("time"),
        202 => String::from("futex"),
        203 => String::from("sched_setaffinity"),
        204 => String::from("sched_getaffinity"),
        205 => String::from("set_thread_area"),
        206 => String::from("io_setup"),
        207 => String::from("io_destroy"),
        208 => String::from("io_getevents"),
        209 => String::from("io_submit"),
        210 => String::from("io_cancel"),
        211 => String::from("get_thread_area"),
        212 => String::from("lookup_dcookie"),
        213 => String::from("epoll_create"),
        214 => String::from("epoll_ctl_old"),
        215 => String::from("epoll_wait_old"),
        216 => String::from("remap_file_pages"),
        217 => String::from("getdents64"),
        218 => String::from("set_tid_address"),
        219 => String::from("restart_syscall"),
        220 => String::from("semtimedop"),
        221 => String::from("fadvise64"),
        222 => String::from("timer_create"),
        223 => String::from("timer_settime"),
        224 => String::from("timer_gettime"),
        225 => String::from("timer_getoverrun"),
        226 => String::from("timer_delete"),
        227 => String::from("clock_settime"),
        228 => String::from("clock_gettime"),
        229 => String::from("clock_getres"),
        230 => String::from("clock_nanosleep"),
        231 => String::from("exit_group"),
        232 => String::from("epoll_wait"),
        233 => String::from("epoll_ctl"),
        234 => String::from("tgkill"),
        235 => String::from("utimes"),
        236 => String::from("vserver"),
        237 => String::from("mbind"),
        238 => String::from("set_mempolicy"),
        239 => String::from("get_mempolicy"),
        240 => String::from("mq_open"),
        241 => String::from("mq_unlink"),
        242 => String::from("mq_timedsend"),
        243 => String::from("mq_timedreceive"),
        244 => String::from("mq_notify"),
        245 => String::from("mq_getsetattr"),
        246 => String::from("kexec_load"),
        247 => String::from("waitid"),
        248 => String::from("add_key"),
        249 => String::from("request_key"),
        250 => String::from("keyctl"),
        251 => String::from("ioprio_set"),
        252 => String::from("ioprio_get"),
        253 => String::from("inotify_init"),
        254 => String::from("inotify_add_watch"),
        255 => String::from("inotify_rm_watch"),
        256 => String::from("migrate_pages"),
        257 => String::from("openat"),
        258 => String::from("mkdirat"),
        259 => String::from("mknodat"),
        260 => String::from("fchownat"),
        261 => String::from("futimesat"),
        262 => String::from("newfstatat"),
        263 => String::from("unlinkat"),
        264 => String::from("renameat"),
        265 => String::from("linkat"),
        266 => String::from("symlinkat"),
        267 => String::from("readlinkat"),
        268 => String::from("fchmodat"),
        269 => String::from("faccessat"),
        270 => String::from("pselect6"),
        271 => String::from("ppoll"),
        272 => String::from("unshare"),
        273 => String::from("set_robust_list"),
        274 => String::from("get_robust_list"),
        275 => String::from("splice"),
        276 => String::from("tee"),
        277 => String::from("sync_file_range"),
        278 => String::from("vmsplice"),
        279 => String::from("move_pages"),
        280 => String::from("utimensat"),
        281 => String::from("epoll_pwait"),
        282 => String::from("signalfd"),
        283 => String::from("timerfd_create"),
        284 => String::from("eventfd"),
        285 => String::from("fallocate"),
        286 => String::from("timerfd_settime"),
        287 => String::from("timerfd_gettime"),
        288 => String::from("accept4"),
        289 => String::from("signalfd4"),
        290 => String::from("eventfd2"),
        291 => String::from("epoll_create1"),
        292 => String::from("dup3"),
        293 => String::from("pipe2"),
        294 => String::from("inotify_init1"),
        295 => String::from("preadv"),
        296 => String::from("pwritev"),
        297 => String::from("rt_tgsigqueueinfo"),
        298 => String::from("perf_event_open"),
        299 => String::from("recvmmsg"),
        300 => String::from("fanotify_init"),
        301 => String::from("fanotify_mark"),
        302 => String::from("prlimit64"),
        303 => String::from("name_to_handle_at"),
        304 => String::from("open_by_handle_at"),
        305 => String::from("clock_adjtime"),
        306 => String::from("syncfs"),
        307 => String::from("sendmmsg"),
        308 => String::from("setns"),
        309 => String::from("getcpu"),
        310 => String::from("process_vm_readv"),
        311 => String::from("process"),
        312 => String::from("process_vm_writev"),
        313 => String::from("kcmp"),
        314 => String::from("finit_module"),
        315 => String::from("sched_setattr"),
        316 => String::from("sched_getattr"),
        317 => String::from("renameat2"),
        318 => String::from("seccomp"),
        319 => String::from("getrandom"),
        320 => String::from("memfd_create"),
        321 => String::from("kexec_file_load"),
        322 => String::from("bpf"),
        323 => String::from("execveat"),
        324 => String::from("userfaultfd"),
        325 => String::from("membarrier"),
        326 => String::from("mlock2"),
        327 => String::from("copy_file_range"),
        328 => String::from("preadv2"),
        329 => String::from("pwritev2"),
        330 => String::from("pkey_mprotect"),
        331 => String::from("pkey_alloc"),
        332 => String::from("pkey_free"),
        333 => String::from("statx"),
        334 => String::from("io_pgetevents"),
        335 => String::from("rseq"),
        336 => String::from("pidfd_send_signal"),
        337 => String::from("io_uring_setup"),
        338 => String::from("io_uring_enter"),
        339 => String::from("io_uring_register"),
        340 => String::from("open_tree"),
        341 => String::from("move_mount"),
        342 => String::from("fsopen"),
        343 => String::from("fsconfig"),
        344 => String::from("fsmount"),
        345 => String::from("fspick"),
        346 => String::from("pidfd_open"),
        347 => String::from("clone3"),
        348 => String::from("close_range"),
        349 => String::from("openat2"),
        350 => String::from("pidfd_getfd"),
        351 => String::from("faccessat2"),
        352 => String::from("process_madvise"),
        353 => String::from("epoll_pwait2"),
        354 => String::from("mount_setattr"),
        355 => String::from("quotactl_fd"),
        356 => String::from("landlock_create_ruleset"),
        357 => String::from("landlock_add_rule"),
        358 => String::from("landlock_restrict_self"),
        359 => String::from("memfd_secret"),
        360 => String::from("process_mrelease"),
        361 => String::from("futex_waitv"),
        362 => String::from("set_mempolicy_home_node"),
        _ => format!("unknown_syscall_{}", syscall_id)
    }
}