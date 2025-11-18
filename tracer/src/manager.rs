use crate::skel_types::{
    SkelAttachUprobe, SkelCheckPidTrait, SkelEndTraceTrait, SkelEnum, SkelUpdatePidTrait,
};
use anyhow::bail;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::Link;
use libbpf_rs::{MapCore, MapFlags};
use nix::net::if_::if_nametoindex;
use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use pin_maps::PinMapsSkel;
use procfs::process::ProcState::{Running, Stopped, Waiting, Zombie};
use procfs::process::Process;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::CStr;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Command;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::thread::{sleep, JoinHandle};
use std::time;
use std::time::Duration;
pub const CONTAINER_TYPE_DOCKER: i32 = 1;
pub const CONTAINER_TYPE_LXC: i32 = 2;
pub const LOCATION_TRACEPOINT_VECTOR: i32 = 0;
use std::fmt;
pub mod pin_maps {
    include!(concat!(env!("OUT_DIR"), "/pin_maps.skel.rs"));
}

#[repr(C)]
pub struct Pair {
    pub src: u32,
    pub dst: u32,
}
#[repr(C)]
pub struct NetworkInfo {
    pub frequency: u32,
    pub last_time_seen: u64,
}

#[repr(C)]
pub struct Event {
    pub event_type: u64,
    pub timestamp: u64,
    pub id: u64,
    pub pid: u32,
    pub tid: u32,
    pub arg1: u32,
    pub arg2: u32,
    pub arg3: u32,
    pub arg4: u32,
    pub ret: i64,
    pub extra: [u8; 256],
}

#[repr(C)]
pub struct Processfd {
    pub fd: i32,
    pub pid: u32,
    pub ts: u64,
}
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct FdData {
    pub pid: u32,
    pub fd: i32,
}

pub struct NameAtTimestamp {
    pub name: String,
    pub timestamp: u64,
}

// Implement Display for custom printing
impl fmt::Debug for NameAtTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name: {}, Timestamp: {} \n", self.name, self.timestamp)
    }
}

static SYSCALLS_WITH_FD: [u64; 8] = [
    0,  // read
    1,  // write
    3,  // close
    32, // dup
    33, // dup2
    34, // pause (uses a signal file descriptor indirectly)
    49, // bind
    439,
];

static _NETWORK_SYSCALLS_WITH_FD: [u64; 10] = [
    40, // sendfile
    41, // socket
    42, // connect
    43, // accept
    44, // sendto
    45, // recvfrom
    46, // sendmsg
    47, // recvmsg
    48, // shutdown
    49, // bind
];

pub mod xdp {
    include!(concat!(env!("OUT_DIR"), "/xdp.skel.rs"));
}

// Prints a TRACER-prefixed message using a preformatted set of arguments.
// Allows ergonomic usage through the `tracer_println!` macro below.
pub fn tracer_println_fmt(args: fmt::Arguments) {
    use std::io::{self, Write};
    let mut stdout = io::stdout().lock();
    // Ignore errors from writeln!/flush to avoid panicking inside logging code.
    let _ = writeln!(stdout, "TRACER: {}", args);
    let _ = stdout.flush();
}

// Macro wrapper so callers can use `tracer_println!` like `println!`.
//
// The macro is exported at crate root and delegates to `tracer_println_fmt`
// via `$crate` so it resolves correctly regardless of call-site context.
#[macro_export]
macro_rules! tracer_println {
    ($($arg:tt)*) => ({
        $crate::manager::tracer_println_fmt(format_args!($($arg)*));
    })
}

pub fn start_tracing(
    mode: String,
    functions: Vec<(String, usize)>,
    binary_path: String,
    nodes_info: String,
    network_device: String,
    skel_enum: &mut SkelEnum<'_, 'static>,
    skel_maps: &mut PinMapsSkel,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    hashmap_node_to_pid: &mut HashMap<String, i32>,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
) -> Result<()> {
    let _xdp_prog;

    if mode == "container" {
        trace_containers(
            nodes_info,
            skel_enum,
            hashmap_pid_to_node,
            hashmap_links,
            functions.clone(),
            binary_path,
        )
        .expect("Failed to trace containers");
    } else if mode == "container_controlled" {
        trace_containers_controlled(
            nodes_info.clone(),
            skel_enum,
            hashmap_pid_to_node,
            hashmap_node_to_pid,
            hashmap_links,
            functions.clone(),
            binary_path,
        )
        .expect("Failed to trace containers controlled");
    } else if mode == "process" {
        trace_processes(
            nodes_info,
            skel_enum,
            hashmap_pid_to_node,
            hashmap_links,
            functions.clone(),
            binary_path,
        )
        .expect("Failed to trace processes");
        let skel_builder = xdp::XdpSkelBuilder::default();
        let mut open_object_tracer = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut open_object_tracer)?;
        let skel = open_skel.load()?;
        if network_device.len() > 0 {
            let if_index = if_nametoindex(network_device.as_str())
                .map_err(|e| e.to_string())
                .unwrap();
            _xdp_prog = skel
                .progs
                .xdp_pass
                .attach_xdp((if_index) as i32)
                .expect("Failed to attach xdp");
        }
    } else if mode == "process_controlled" {
        let skel_builder = xdp::XdpSkelBuilder::default();
        let mut open_object_tracer = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut open_object_tracer)?;
        let skel_xdp = open_skel.load()?;
        if network_device.len() > 0 {
            let if_index = if_nametoindex(network_device.as_str())
                .map_err(|e| e.to_string())
                .unwrap();
            _xdp_prog = skel_xdp
                .progs
                .xdp_pass
                .attach_xdp((if_index) as i32)
                .expect("Failed to attach xdp");
        }
        trace_processes_controlled(
            nodes_info,
            skel_enum,
            hashmap_pid_to_node,
            hashmap_node_to_pid,
            hashmap_links,
            functions.clone(),
            binary_path,
        )
        .expect("Failed to trace processes controlled");
    }
    skel_enum.end_trace(skel_maps, hashmap_pid_to_node, functions);

    Ok(())
}
pub fn trace_processes(
    nodes_info: String,
    skel: &mut SkelEnum,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<(String, usize)>,
    binary_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut join_handles = vec![];
    let mut tx_handles = vec![];
    let path = nodes_info;
    let file: File = File::open(&path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() == 2 {
            let node_name = parts[0].trim();
            let pid: i32 = match parts[1].trim().parse() {
                Ok(num) => num,
                Err(_) => {
                    tracer_println!("Failed to parse integer on line: {}", line);
                    continue;
                }
            };

            let pid_vec = u32_to_u8_array_little_endian(pid);
            let one = u32_to_u8_array_little_endian(1);

            skel.update(&pid_vec, &one);
            hashmap_pid_to_node.insert(pid, node_name.to_string().clone());
            let (tx, rx) = mpsc::channel();
            tx_handles.push(tx);
            start_tracing_process(
                pid,
                node_name.to_string(),
                hashmap_links,
                functions.clone(),
                binary_path.clone(),
                skel,
                rx,
                &mut join_handles,
            );
        } else {
            tracer_println!("Incorrect format on line: {}", line);
        }
    }

    write_to_file("check.txt".to_string(), "ready".to_string()).expect("Failed to write to file");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_secs(1));
    }

    Ok(())
}
pub fn start_tracing_process(
    pid: i32,
    container_name: String,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<(String, usize)>,
    binary_path: String,
    skel: &mut SkelEnum,
    rx: Receiver<()>,
    join_handles: &mut Vec<JoinHandle<()>>,
) {
    tracer_println!(
        "Started tracing for pid {} with node_name {}",
        pid,
        container_name
    );

    hashmap_links.insert(pid, vec![]);

    let handle = thread::spawn(move || {
        monitor_pid(pid, rx).expect("Monitoring failed");
    });

    join_handles.push(handle);

    for (index_function, function) in functions.clone().iter().enumerate() {
        skel.attach_uprobe(
            index_function,
            &function.0,
            function.1,
            binary_path.clone(),
            pid,
            hashmap_links,
        );
    }
}

pub fn trace_containers(
    nodes_info: String,
    skel: &mut SkelEnum<'_, 'static>,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    mut hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<(String, usize)>,
    binary_path: String,
) -> Result<()> {
    let mut join_handles = vec![];
    let mut tx_handles = vec![];

    let path = nodes_info;
    let file: File = File::open(&path).expect("File not found");
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(',').collect();

        if parts.len() == 3 {
            let node_name = parts[0].trim();
            let pid: i32 = match parts[1].trim().parse() {
                Ok(num) => num,
                Err(_) => {
                    tracer_println!("Failed to parse integer on line: {}", line);
                    continue;
                }
            };
            let veth = parts[2].trim();

            let veth_index = if_nametoindex(veth).map_err(|e| e.to_string()).unwrap();

            let pid_vec = u32_to_u8_array_little_endian(pid);
            let one = u32_to_u8_array_little_endian(1);
            skel.update(&pid_vec, &one);

            hashmap_pid_to_node.insert(pid, node_name.to_string().clone());

            let (tx, rx) = mpsc::channel();
            tx_handles.push(tx);
            //CONTAINER_TYPE_DOCKER is temporary
            start_tracing_container(
                pid,
                CONTAINER_TYPE_DOCKER,
                node_name.to_string(),
                &mut hashmap_links,
                functions.clone(),
                binary_path.clone(),
                skel,
                rx,
                &mut join_handles,
                false,
            );
            start_xdp_in_container(pid, (veth_index) as i32, CONTAINER_TYPE_DOCKER);
        } else {
            tracer_println!("Incorrect format on line: {}", line);
        }
    }

    write_to_file("check.txt".to_string(), "ready".to_string()).expect("Failed to write to file");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        //TODO: Check for bug
        sleep(Duration::from_secs(1));
    }

    for tx in tx_handles {
        let send_res = tx.send(());

        match send_res {
            Ok(_) => {
                //tracer_println!("Sent successfully")
            }
            Err(e) => tracer_println!("Error sending: {}", e),
        }
    }

    for handle in join_handles {
        let result = handle.join();

        match result {
            Ok(_) => {
                //tracer_println!("Thread finished successfully")
            }
            Err(_e) => tracer_println!("Thread finished with an error"),
        }
    }

    Ok(())
}

pub fn start_tracing_container(
    pid: i32,
    container_type: i32,
    container_name: String,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<(String, usize)>,
    binary_path: String,
    skel: &mut SkelEnum<'_, 'static>,
    rx: Receiver<()>,
    join_handles: &mut Vec<JoinHandle<()>>,
    controlled: bool,
) {
    tracer_println!(
        "Started tracing for pid {} with node_name {}",
        pid,
        container_name
    );
    //hashmap_links.insert(pid, vec![]);

    // let mut container_location = "".to_string();
    // if container_type == CONTAINER_TYPE_DOCKER {
    //     container_location = get_overlay2_location(&container_name).unwrap();
    // }
    // if container_type == CONTAINER_TYPE_LXC {
    //     container_location = get_lxc_rootfs_location(&container_name);
    // }

    // let binary_location = format!("{}{}", container_location, binary_path);

    // for (index_function, function) in functions.clone().iter().enumerate() {
    //     skel.attach_uprobe(
    //         index_function,
    //         &function.0,
    //         function.1,
    //         binary_location.clone(),
    //         pid,
    //         hashmap_links,
    //     );
    // }
    let handle;
    if controlled {
        handle = thread::spawn(move || {
            monitor_pid_controlled(pid, rx).expect("Monitoring failed");
        });
    } else {
        handle = thread::spawn(move || {
            monitor_pid(pid, rx).expect("Monitoring failed");
        });
    }
    join_handles.push(handle);
    tracer_println!("Finished adding uprobes for node {}", container_name);
}

pub fn trace_containers_controlled(
    nodes_info: String,
    skel: &mut SkelEnum<'_, 'static>,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    hashmap_node_to_pid: &mut HashMap<String, i32>,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<(String, usize)>,
    binary_path: String,
) -> Result<()> {
    let mut join_handles = vec![];
    let mut xdp_pids = vec![];
    let mut tx_handles = vec![];
    //Loop read from a pipe to get pid+container
    let read_pipe_name = format!("{}_write", nodes_info.clone());
    let write_pipe_name = format!("{}_read", nodes_info.clone());

    //In docker the same file (inode and stuff) is shared thus we only need to attach one time, even if the paths are different
    let mut probes_attached = false;

    if Path::new(&read_pipe_name).exists() {
        let file = File::open(read_pipe_name.clone()).unwrap();
        tracer_println!("Opening FIFO for reading...{}", read_pipe_name.clone());
        let reader = BufReader::new(file);

        let mut file_write = OpenOptions::new()
            .write(true)
            .open(&write_pipe_name)
            .unwrap();

        for line in reader.lines() {
            let line = line?;
            if line == "finished" {
                break;
            }
            tracer_println!("RECEIVED:{}", line);
            let parts: Vec<&str> = line.split(',').collect();

            let node_name = parts[0].to_string();

            let container_pid: i32 = parts[1].parse().unwrap();

            let pid: i32 = parts[2].parse().unwrap();

            let if_index: i32 = parts[3].parse().unwrap();

            let container_type: i32 = parts[4].parse().unwrap();

            let pid_vec = u32_to_u8_array_little_endian(pid);
            let one = u32_to_u8_array_little_endian(1);
            skel.update(&pid_vec, &one);

            while !skel.check(&pid_vec) {}

            let (tx, rx) = mpsc::channel();
            tx_handles.push(tx);

            let mut container_location = "".to_string();
            if container_type == CONTAINER_TYPE_DOCKER {
                container_location = get_overlay2_location(&node_name).unwrap();
            }
            if container_type == CONTAINER_TYPE_LXC {
                container_location = get_lxc_rootfs_location(&node_name);
            }
            //Hold the references to the uprobes so they are not dropped
            hashmap_links.insert(pid, vec![]);

            let binary_location = format!("{}{}", container_location, binary_path);

            //tracer_println!("BINARY LOCATION: {}", binary_location);

            if !probes_attached {
                for (index_function, function) in functions.clone().iter().enumerate() {
                    skel.attach_uprobe(
                        index_function,
                        &function.0,
                        function.1,
                        binary_location.clone(),
                        pid,
                        hashmap_links,
                    );
                }
                probes_attached = true;
            }
            start_tracing_container(
                pid,
                container_type,
                node_name.clone(),
                hashmap_links,
                functions.clone(),
                binary_path.clone(),
                skel,
                rx,
                &mut join_handles,
                true,
            );

            let node_already_traced = hashmap_node_to_pid.get(&node_name.clone()).is_some();

            if !node_already_traced {
                if if_index != 0 {
                    let pid = start_xdp_in_container(container_pid, if_index, container_type);
                    xdp_pids.push(pid);
                }
            }

            hashmap_pid_to_node.insert(pid, node_name.clone());
            hashmap_node_to_pid.insert(node_name.clone(), pid);

            let msg = b"DONE\n";

            file_write
                .write_all(msg)
                .expect("Failed to send ping to ROSE");
        }
    } else {
        tracer_println!("FIFO does not exist.");
    }

    for tx in tx_handles {
        let send_res = tx.send(());

        match send_res {
            Ok(_) => tracer_println!("Sent successfully"),
            Err(e) => tracer_println!("Error sending: {}", e),
        }
    }

    for handle in join_handles {
        let result = handle.join();

        match result {
            Ok(_) => tracer_println!("Thread finished successfully"),
            Err(_e) => tracer_println!("Thread finished with an error"),
        }
    }

    for pid in xdp_pids {
        let pid = Pid::from_raw(pid as i32);
        kill(pid, Signal::SIGKILL).expect("Failed to kill xdp_pid");
    }
    tracer_println!("Finished tracing containers");

    Ok(())
}

pub fn trace_processes_controlled(
    nodes_info: String,
    skel: &mut SkelEnum<'_, 'static>,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    hashmap_node_to_pid: &mut HashMap<String, i32>,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<(String, usize)>,
    binary_path: String,
) -> Result<()> {
    let mut join_handles = vec![];
    let mut tx_handles = vec![];
    let read_pipe_name = format!("{}_write", nodes_info.clone());
    let write_pipe_name = format!("{}_read", nodes_info.clone());
    if Path::new(&read_pipe_name).exists() {
        let file = File::open(read_pipe_name.clone()).unwrap();
        tracer_println!("Opening FIFO for reading...{}", read_pipe_name.clone());
        let reader = BufReader::new(file);

        let mut file_write = OpenOptions::new()
            .write(true)
            .open(&write_pipe_name)
            .unwrap();

        for line in reader.lines() {
            let line = line?;

            tracer_println!("Received:{}", line);

            if line == "finished" {
                break;
            }

            let parts: Vec<&str> = line.split(',').collect();

            let node_name = parts[0].to_string();

            let _container_pid: i32 = parts[1].parse().unwrap();

            let pid: i32 = parts[2].parse().unwrap();

            let _if_index: i32 = parts[3].parse().unwrap();

            let pid_vec = u32_to_u8_array_little_endian(pid);

            let one = u32_to_u8_array_little_endian(1);

            skel.update(&pid_vec, &one);

            hashmap_pid_to_node.insert(pid, node_name.clone());
            hashmap_node_to_pid.insert(node_name.clone(), pid);

            let (tx, rx) = mpsc::channel();
            tx_handles.push(tx);
            start_tracing_process(
                pid,
                node_name.clone(),
                hashmap_links,
                functions.clone(),
                binary_path.clone(),
                skel,
                rx,
                &mut join_handles,
            );
            let buf = vec![0; 8];
            file_write.write(&buf).expect("Failed to send ping to ROSE");
        }
    } else {
        tracer_println!("FIFO does not exist.");
    }

    for tx in tx_handles {
        let send_res = tx.send(());

        match send_res {
            Ok(_) => tracer_println!("Sent successfully"),
            Err(e) => tracer_println!("Error sending: {}", e),
        }
    }

    for handle in join_handles {
        let result = handle.join();

        match result {
            Ok(_) => tracer_println!("Thread finished successfully"),
            Err(_e) => tracer_println!("Thread finished with an error"),
        }
    }

    Ok(())
}

pub fn end_trace(
    pid_tree: &libbpf_rs::Map,
    fd_to_name: &libbpf_rs::Map,
    dup_map: &libbpf_rs::Map,
    network_information: &libbpf_rs::Map,
    history_delays: &libbpf_rs::Map,
    history: &libbpf_rs::Map,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    functions: &Vec<(String, usize)>,
) {
    create_pid_tree(pid_tree, hashmap_pid_to_node);

    let mut filenames = collect_fd_map(fd_to_name, dup_map);

    collect_network_info(network_information);

    collect_network_delays(history_delays);

    collect_events(
        history,
        functions.clone(),
        hashmap_pid_to_node,
        &mut filenames,
    );
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
            Err(e) => tracer_println!("Error parsing number '{}': {}", line, e),
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

pub fn vec_to_i32(bytes: Vec<u8>) -> i32 {
    let byte_array: [u8; 4] = bytes
        .try_into()
        .expect("Vec<u8> must have exactly 4 elements");
    i32::from_le_bytes(byte_array)
}

pub fn write_to_file(filename: String, content: String) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)?;
    file.write_all(content.as_bytes())?;

    file.flush()?;

    Ok(())
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

pub fn get_lxc_rootfs_location(container_name: &str) -> String {
    let base_path = "/var/snap/lxd/common/lxd/storage-pools/default/containers";
    let container_path = format!("{}/{}/rootfs", base_path, container_name);
    return container_path;
}

pub fn read_names_from_file(filename: &str) -> io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
    Ok(lines)
}

pub fn remove_duplicates(vec: Vec<u64>) -> Vec<u64> {
    let mut seen = HashSet::new();
    vec.into_iter().filter(|&x| seen.insert(x)).collect()
}
pub fn collect_fd_map(
    fd_to_name: &libbpf_rs::Map,
    dup_map: &libbpf_rs::Map,
) -> HashMap<FdData, Vec<NameAtTimestamp>> {
    let mut filenames: HashMap<FdData, Vec<NameAtTimestamp>> = HashMap::new();

    let keys = fd_to_name.keys();

    for key in keys {
        let result = fd_to_name.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let value = result.unwrap().clone();

                unsafe {
                    let process_fd: *const Processfd = key.as_ptr() as *const Processfd;

                    let process_fd: &Processfd = &*process_fd;

                    if process_fd.pid == 0 {
                        tracer_println!("Pid is 0");
                        continue;
                    }
                    let c_str =
                        CStr::from_bytes_until_nul(&value).expect("Failed to call from_bytes");
                    let name = c_str
                        .to_str()
                        .expect("Failed to convert to rust_string")
                        .to_owned();

                    let pid = process_fd.pid;

                    let fd = process_fd.fd;

                    let timestamp = process_fd.ts;

                    let fd_data = FdData { pid, fd };

                    let name_at_ts = NameAtTimestamp { name, timestamp };

                    let list_filenames = filenames.get_mut(&fd_data);

                    match list_filenames {
                        Some(list_filenames) => {
                            list_filenames.push(name_at_ts);
                        }
                        None => {
                            let mut list = vec![];
                            list.push(name_at_ts);
                            filenames.insert(fd_data, list);
                        }
                    };
                }
            }
            Err(e) => {
                tracer_println!("Err: {:?}", e);
            }
        }
    }

    let keys = dup_map.keys();

    for key in keys {
        let result = dup_map.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let value = result.unwrap().clone();

                unsafe {
                    let process_fd: *const Processfd = key.as_ptr() as *const Processfd;

                    let process_fd: &Processfd = &*process_fd;

                    if process_fd.pid == 0 {
                        tracer_println!("Pid is 0");
                        continue;
                    }

                    //tracer_println!("Pid is {} fd is {} at ts {} with name {}",process_fd.pid,process_fd.fd,process_fd.ts,rust_string);

                    let pid = process_fd.pid;

                    let old_fd = process_fd.fd;

                    let dup_timestamp = process_fd.ts;

                    let old_fd_data = FdData { pid, fd: old_fd };

                    let list_filenames = filenames.get_mut(&old_fd_data);

                    let mut name = "".to_string();
                    let mut current_ts = 0;
                    match list_filenames {
                        Some(list_filenames) => {
                            for filename_and_ts in list_filenames {
                                if (dup_timestamp > filename_and_ts.timestamp)
                                    && (current_ts < filename_and_ts.timestamp)
                                {
                                    name = filename_and_ts.name.to_string();
                                    current_ts = filename_and_ts.timestamp;
                                }
                            }
                        }
                        None => {
                            tracer_println!(
                                "FD with no matching file, probably a read from socket"
                            );
                        }
                    };

                    let byte_array: [u8; 4] = [value[0], value[1], value[2], value[3]];
                    let fd = i32::from_le_bytes(byte_array);

                    let fd_data = FdData { pid, fd };

                    let name_at_ts = NameAtTimestamp {
                        name,
                        timestamp: dup_timestamp,
                    };

                    let list_filenames = filenames.get_mut(&fd_data);

                    match list_filenames {
                        Some(list_filenames) => {
                            list_filenames.push(name_at_ts);
                        }
                        None => {
                            let mut list = vec![];
                            list.push(name_at_ts);
                            filenames.insert(fd_data, list);
                        }
                    };
                }
            }
            Err(e) => {
                tracer_println!("Err: {:?}", e);
            }
        }
    }

    return filenames;
}

//Get all pids created by initial nodes, and assigns them a node_name
pub fn create_pid_tree(pids: &libbpf_rs::Map, hashmap_pid_to_node: &mut HashMap<i32, String>) {
    let mut pid_parent_map: HashMap<u32, u32> = HashMap::new();

    let keys = pids.keys();

    for key in keys {
        let result = pids.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let parent = result.unwrap().clone();

                unsafe {
                    let child: *const u32 = key.as_ptr() as *const u32;
                    let child: &u32 = &*child;

                    let parent: *const u32 = parent.as_ptr() as *const u32;
                    let parent: &u32 = &*parent;

                    //Child 0 means empty key, parent == 1 means origin pid
                    if *child == 0 {
                        continue;
                    }
                    pid_parent_map.insert(*child, *parent);
                }
            }
            Err(e) => {
                tracer_println!("Err: {:?}", e);
            }
        }
    }

    for (&pid, parent_pid) in &pid_parent_map {
        let first_pid = pid;
        let mut origin_pid = pid;
        let mut temp_parent = parent_pid.clone();

        // Traverse up the parent tree
        while let Some(&new_parent) = pid_parent_map.get(&temp_parent) {
            if new_parent == 1 {
                origin_pid = temp_parent;
                break;
            }
            origin_pid = new_parent;
            temp_parent = new_parent;
        }

        let node_name = hashmap_pid_to_node
            .get(&origin_pid.try_into().unwrap_or(0))
            .expect(format!("Did not find an origin node for this pid {}", origin_pid).as_str());

        hashmap_pid_to_node.insert(first_pid.try_into().unwrap_or(0), node_name.clone());
    }

    let mut origin_pids: Vec<(u32, String)> = vec![];

    for (&pid, parent_pid) in &pid_parent_map {
        let node_name = hashmap_pid_to_node
            .get(&pid.try_into().unwrap_or(0))
            .expect(format!("Did not find an origin node for this pid {}", pid).as_str());

        let parent = pid_parent_map.get(&pid);
        match parent {
            Some(p) => {
                if *p == 1 {
                    origin_pids.push((pid, node_name.clone()));
                }
            }
            None => {
                origin_pids.push((pid, node_name.clone()));
            }
        }
    }

    // for pair in &origin_pids {
    //     write_to_file(
    //         "/tmp/pid_tree.txt".to_string(),
    //         format!("{},{}\n", pair.0, pair.1),
    //     )
    //     .expect("Failed to write to pid_tree file");
    // }

    // tracer_println!("{:?}", origin_pids);
}

pub fn collect_events(
    called_functions: &libbpf_rs::Map,
    functions: Vec<(String, usize)>,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    filenames: &mut HashMap<FdData, Vec<NameAtTimestamp>>,
) {
    let keys = called_functions.keys();
    //Use later
    let mut history: Vec<&Event> = vec![];

    for key in keys {
        let result = called_functions.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let event = result.unwrap().clone();

                unsafe {
                    let event: *const Event = event.as_ptr() as *const Event;
                    let event: &Event = &*event;

                    if event.pid == 0 {
                        continue;
                    }

                    history.push(event);

                    if event.event_type == 1 {
                        let mut filename = "na".to_string();

                        if SYSCALLS_WITH_FD.contains(&event.id) {
                            filename = find_filename(event, filenames);
                        }
                        //tracer_println!("Added sys_enter with ret {}",event.ret);
                        let pid = event.pid as i32;
                        let event_name = get_syscall_name(event.id);
                        let node_name = hashmap_pid_to_node
                            .get(&pid)
                            .expect(&format!("Failed to node-name for pid {}", event.pid));
                        write_event_to_history(
                            event,
                            node_name.clone(),
                            "sys_enter".to_string(),
                            event_name,
                            filename,
                        );
                    }
                    if event.event_type == 2 {
                        //tracer_println!("Added sys_exit with ret {}",event.ret);
                        let mut filename = "na".to_string();

                        if SYSCALLS_WITH_FD.contains(&event.id) {
                            filename = find_filename(event, filenames);
                        } else if event.id == 262 || event.id == 257 {
                            let c_string = event.extra.split(|&c| c == 0).next().unwrap_or(&[]);
                            filename = String::from_utf8_lossy(c_string).to_string()
                        }

                        let pid = event.pid as i32;
                        let event_name = get_syscall_name(event.id);
                        let node_name = hashmap_pid_to_node
                            .get(&pid)
                            .expect(&format!("Failed to node-name for pid {}", event.pid));
                        write_event_to_history(
                            event,
                            node_name.clone(),
                            "sys_exit".to_string(),
                            event_name,
                            filename,
                        );
                    }
                    if event.event_type == 3 {
                        let pid = event.pid as i32;
                        let node_name = hashmap_pid_to_node
                            .get(&pid)
                            .expect(&format!("Failed to node-name for pid {}", event.pid));
                        let event_name = functions.get(event.id as usize);

                        let event_name = match event_name {
                            Some((name, offset)) => &(name.clone(), *offset),
                            None => &("unknown".to_string(), 0 as usize),
                        };

                        if event_name.0 == "unknown" {
                            continue;
                        }
                        write_event_to_history(
                            event,
                            node_name.clone(),
                            "function_call".to_string(),
                            event_name.0.clone(),
                            "na".to_string(),
                        );
                    }
                }
            }
            Err(e) => {
                tracer_println!("Err: {:?}", e);
            }
        }
    }
}

pub fn process_uprobes_counters_map(
    uprobes_counters_map: &libbpf_rs::Map,
    functions: &Vec<(String, usize)>,
) {
    let keys = uprobes_counters_map.keys();

    let mut uprobes_counters: Vec<i32> = vec![0; 4096];

    let mut total_function_call = 0;
    for key in keys {
        let result = uprobes_counters_map.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let cookie = vec_to_i32(key);

                let value_vec = result.unwrap().clone();

                let value = vec_to_i32(value_vec);

                total_function_call += value;

                uprobes_counters[cookie as usize] = value;
            }
            Err(e) => {
                tracer_println!("Err: {:?}", e);
            }
        }
    }

    tracer_println!("Total function calls: {}", total_function_call);

    File::create("/tmp/function_stats.txt").expect("Failed to create file");

    for (index, value) in uprobes_counters.iter().enumerate() {
        if *value > 0 {
            write_to_file(
                "/tmp/function_stats.txt".to_string(),
                format!("{},{},{}\n", functions[index].0, functions[index].1, value),
            )
            .expect("Failed to write to stats file");
        }
    }
}

pub fn process_syscall_counters_map(
    syscall_counters_map: &libbpf_rs::Map,
    functions: &Vec<(String, usize)>,
) {
    let keys = syscall_counters_map.keys();

    let mut syscall_counters: Vec<i32> = vec![0; 4096];

    for key in keys {
        let result = syscall_counters_map.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let cookie = vec_to_i32(key);

                let value_vec = result.unwrap().clone();

                let value = vec_to_i32(value_vec);

                syscall_counters[cookie as usize] = value;
            }
            Err(e) => {
                tracer_println!("Err: {:?}", e);
            }
        }
    }

    File::create("/tmp/syscall_stats.txt").expect("Failed to create file");

    for (index, value) in syscall_counters.iter().enumerate() {
        if *value > 0 {
            write_to_file(
                "/tmp/syscall_stats.txt".to_string(),
                format!("{},{}\n", get_syscall_name(index as u64), value),
            )
            .expect("Failed to write to stats file");
        }
    }
}

pub fn monitor_pid(
    pid: i32,
    stop_signal: mpsc::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sleep_duration = time::Duration::from_millis(1000);
    let mut events_process_pause = vec![];
    let check_process = Process::new(pid);
    let process = match check_process {
        Ok(process_alive) => process_alive,
        Err(e) => {
            tracer_println!("Process with PID {} not found: {}", pid, e);
            return Ok(());
        }
    };
    let mut duration = 0;
    let mut state = Running;
    //Default process is Running
    loop {
        if stop_signal.try_recv().is_ok() {
            tracer_println!("Stopping monitoring for PID:{}", pid);
            break;
        }

        // Fetch process information
        let p_info = process.stat();
        let timestamp = std::time::Duration::from(nix::time::clock_gettime(
            nix::time::ClockId::CLOCK_MONOTONIC,
        )?)
        .as_nanos();
        match p_info {
            Ok(p_info) => {
                state = p_info.state().unwrap();
                if state == Waiting || state == Stopped {
                    duration += 1;
                    tracer_println!("Process detected as stopped");
                }
                //If the process was waiting/stopped for more than 3 seconds we generate an event and clear the variables
                else if duration > 3 {
                    let event = Event {
                        event_type: 5,
                        id: 0,
                        pid: pid as u32,
                        tid: 0,
                        timestamp: timestamp as u64,
                        ret: 0,
                        arg1: state as u32,
                        arg2: duration,
                        arg3: 0,
                        arg4: 0,
                        extra: [0; 256],
                    };
                    events_process_pause.push(event);
                    duration = 0;
                } else if state != Waiting && state != Stopped {
                    duration = 0;
                }
                //TODO: Maybe usefull in other scenarios
                // if state == Zombie {
                //     //Process finished event
                //     let event = Event {
                //         event_type: 6,
                //         id: 0,
                //         pid: pid as u32,
                //         tid: 0,
                //         timestamp: timestamp as u64,
                //         ret: 0,
                //         arg1: state as u32,
                //         arg2: duration,
                //         arg3: 0,
                //         arg4: 0,
                //         extra: [0; 256],
                //     };
                //     //events_process_pause.push(event);
                //     tracer_println!("PROCESS:{} DEAD, ADDING EVENT", pid);
                //     break;
                // }
                thread::sleep(sleep_duration);
            }
            Err(e) => {
                if duration > 3 {
                    let event = Event {
                        event_type: 5,
                        id: 0,
                        pid: pid as u32,
                        tid: 0,
                        timestamp: timestamp as u64,
                        ret: 0,
                        arg1: state as u32,
                        arg2: duration,
                        arg3: 0,
                        arg4: 0,
                        extra: [0; 256],
                    };
                    events_process_pause.push(event);
                }
                tracer_println!("Finished tracing for PID:{}", pid);
                break;
            }
        }
    }
    tracer_println!("Monitoring process with PID finished {} has exited.", pid);

    for event in events_process_pause {
        let event_name = "process_state_change".to_string();
        let node_name = "any".to_string();
        write_event_to_history(
            &event,
            node_name,
            event_name.to_string(),
            event_name,
            "na".to_string(),
        );
    }

    Ok(())
}

pub fn monitor_pid_controlled(
    pid: i32,
    stop_signal: mpsc::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sleep_duration = time::Duration::from_millis(1000);
    let mut events_process_pause = vec![];

    // Ensure the original PID exists first
    let check_process = Process::new(pid);
    let _process = match check_process {
        Ok(process_alive) => process_alive,
        Err(e) => {
            tracer_println!("Process with PID {} not found: {}", pid, e);
            return Ok(());
        }
    };

    //tracer_println!("Waiting for PID {} to spawn a child...", pid);

    // PHASE 1: wait for a child of `pid
    let child = find_child(pid, &stop_signal);
    if child == 0 {
        return Ok(());
    }
    // PHASE 2: wait for the child to spawn its own child (grandchild)
    let grandchild = find_child(child, &stop_signal);
    if grandchild == 0 {
        return Ok(());
    }
    // PHASE 3: start monitoring the grandchild PID (target)
    let target_pid = grandchild;

    tracer_println!("Switching to monitoring PID {}", target_pid);

    let check_target = Process::new(target_pid);
    let process = match check_target {
        Ok(p) => p,
        Err(e) => {
            tracer_println!("Target process {} not found: {}", target_pid, e);
            return Ok(());
        }
    };

    let mut duration = 0;
    let mut state = Running;

    loop {
        if stop_signal.try_recv().is_ok() {
            tracer_println!("Stopping monitoring for PID:{}", target_pid);
            break;
        }

        let p_info = process.stat();
        let timestamp = std::time::Duration::from(nix::time::clock_gettime(
            nix::time::ClockId::CLOCK_MONOTONIC,
        )?)
        .as_nanos();
        match p_info {
            Ok(p_info) => {
                state = p_info.state().unwrap();
                if state == Waiting || state == Stopped {
                    duration += 1;
                }
                //If the process was waiting/stopped for more than 3 seconds we generate an event and clear the variables
                else if duration > 3 {
                    let event = Event {
                        event_type: 5,
                        id: 0,
                        pid: target_pid as u32,
                        tid: 0,
                        timestamp: timestamp as u64,
                        ret: 0,
                        arg1: Waiting as u32,
                        arg2: duration,
                        arg3: 0,
                        arg4: 0,
                        extra: [0; 256],
                    };
                    events_process_pause.push(event);
                    tracer_println!("PROCESS:{} NO LONGER PAUSED, ADDING EVENT", target_pid);
                    duration = 0;
                } else if state != Waiting && state != Stopped {
                    duration = 0;
                } else if state == Zombie {
                    //Process finished event
                    let event = Event {
                        event_type: 6,
                        id: 0,
                        pid: target_pid as u32,
                        tid: 0,
                        timestamp: timestamp as u64,
                        ret: 0,
                        //1 Represents process death
                        arg1: 1,
                        arg2: duration,
                        arg3: 0,
                        arg4: 0,
                        extra: [0; 256],
                    };
                    tracer_println!("PROCESS:{} DEAD, ADDING EVENT", target_pid);
                    events_process_pause.push(event);
                    break;
                }

                thread::sleep(sleep_duration);
            }
            Err(_e) => {
                if duration > 3 {
                    let event = Event {
                        event_type: 5,
                        id: 0,
                        pid: target_pid as u32,
                        tid: 0,
                        timestamp: timestamp as u64,
                        ret: 0,
                        arg1: state as u32,
                        arg2: duration,
                        arg3: 0,
                        arg4: 0,
                        extra: [0; 256],
                    };
                    events_process_pause.push(event);
                }

                let event = Event {
                    event_type: 6,
                    id: 0,
                    pid: target_pid as u32,
                    tid: 0,
                    timestamp: timestamp as u64,
                    ret: 0,
                    arg1: state as u32,
                    arg2: duration,
                    arg3: 0,
                    arg4: 0,
                    extra: [0; 256],
                };
                tracer_println!("PROCESS:{} DEAD, ADDING EVENT", target_pid);
                events_process_pause.push(event);
                break;
            }
        }
    }

    for event in events_process_pause {
        let event_name = "process_state_change".to_string();
        let node_name = "any".to_string();
        write_event_to_history(
            &event,
            node_name,
            event_name.to_string(),
            event_name,
            "na".to_string(),
        );
    }

    Ok(())
}

pub fn find_child(pid: i32, stop_signal: &mpsc::Receiver<()>) -> i32 {
    let mut child_pid: Option<i32> = None;
    loop {
        if stop_signal.try_recv().is_ok() {
            tracer_println!("Stopping search for child");
            return 0;
        }
        if let Ok(all_procs) = procfs::process::all_processes() {
            for proc_res in all_procs {
                if let Ok(p) = proc_res {
                    if let Ok(stat) = p.stat() {
                        if stat.ppid == pid {
                            child_pid = Some(p.pid);
                            //tracer_println!("Found child PID {} of parent {}", p.pid, pid);
                            break;
                        }
                    }
                }
            }
        }

        if child_pid.is_some() {
            return child_pid.unwrap();
        }
        thread::sleep(time::Duration::from_millis(50));
    }
}

pub fn collect_network_delays(network_delays: &libbpf_rs::Map) {
    let keys = network_delays.keys();

    let mut history: Vec<&Event> = vec![];
    for key in keys {
        let result = network_delays.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let event = result.unwrap().clone();

                unsafe {
                    let event: *const Event = event.as_ptr() as *const Event;
                    let event: &Event = &*event;

                    if event.pid == 0 {
                        continue;
                    }

                    history.push(event);

                    if event.event_type == 4 {
                        write_event_to_history(
                            event,
                            "any".to_string(),
                            "network_event".to_string(),
                            "network_delay".to_string(),
                            "na".to_string(),
                        );
                    }
                    //tracer_println!("Found delay from {} to {} of {}",Ipv4Addr::from(event.arg1),Ipv4Addr::from(event.arg2),event.arg3);
                }
            }
            Err(e) => {
                tracer_println!("Err: {:?}", e);
            }
        }
    }
}
pub fn collect_network_info(network_info: &libbpf_rs::Map) {
    let keys = network_info.keys();
    for key in keys {
        unsafe {
            let net_pair = key.as_ptr() as *const Pair;

            let net_pair: &Pair = &*net_pair;

            let result = network_info.lookup(&key, MapFlags::ANY).unwrap();

            match result {
                Some(result) => {
                    let net_info_pair: *const NetworkInfo = result.as_ptr() as *const NetworkInfo;

                    let net_info: &NetworkInfo = &*net_info_pair;

                    let src: u32 = net_pair.src;
                    let dst: u32 = net_pair.dst;

                    let frequency: u32 = net_info.frequency;
                    let last_time_seen: u64 = net_info.last_time_seen;

                    let event = Event {
                        event_type: 6,
                        id: 0,
                        pid: 0,
                        tid: 0,
                        timestamp: last_time_seen,
                        ret: 0,
                        arg1: src,
                        arg2: dst,
                        arg3: frequency,
                        arg4: 0,
                        extra: [0; 256],
                    };
                    write_event_to_history(
                        &event,
                        "any".to_string(),
                        "network_information".to_string(),
                        "network_information".to_string(),
                        "na".to_string(),
                    );
                }
                None => {
                    tracer_println!("No value found for key: {:?}", key);
                    continue;
                }
            }
        }
    }
}

pub fn write_event_to_history(
    event: &Event,
    node_name: String,
    event_type: String,
    event_name: String,
    filename: String,
) {
    write_to_file("/tmp/history.txt".to_string(),
    format!("Node:{},Pid:{},Tid:{},event_type:{},event_name:{},ret:{},time:{},arg1:{},arg2:{},arg3:{},arg4:{},arg5:{}\n",
    node_name,event.pid,event.tid,event_type,event_name,event.ret,event.timestamp,event.arg1,event.arg2,event.arg3,event.arg4,filename)).expect("Failed to dump history");
}

pub fn start_xdp_in_container(container_pid: i32, if_index: i32, container_type: i32) -> u32 {
    // Create the `nsenter` command
    let child = Command::new("nsenter")
        .arg(format!("-t {}", container_pid)) // Specify the network namespace
        .arg("-n")
        .arg("/vagrant/tracer/target/release/xdp")
        .arg(format!("{}", if_index))
        .arg(format!("{}", container_type))
        .spawn()
        .expect("Failed to start XDP");

    let child_pid = child.id();

    return child_pid;
}

pub fn find_filename(
    event: &Event,
    filenames: &mut HashMap<FdData, Vec<NameAtTimestamp>>,
) -> String {
    let fd = event.arg1 as i32;
    let pid = event.pid;

    let event_ts = event.timestamp;

    let fd_data = FdData { pid, fd };

    let filename_list = filenames.get(&fd_data);

    let mut filename = "na".to_string();

    let mut current_ts = 0;

    //Have to check ts of name events since we collect from an hashmap which is not ordered
    match filename_list {
        Some(filename_list) => {
            for (i, name_ts) in filename_list.iter().enumerate() {
                if (event_ts > name_ts.timestamp) && (current_ts < name_ts.timestamp) {
                    filename = filename_list[i].name.to_string();
                    current_ts = name_ts.timestamp;
                }
            }
        }
        None => {}
    };
    //tracer_println!("Filename: {} for fd {} and pid {}",filename,fd,pid);
    return filename;
}

pub fn parse_file_to_pairs(filename: &str) -> Vec<(String, usize)> {
    tracer_println!("Collecting function pairs from file: {}", filename);
    let file = File::open(filename).expect("Failed to open file");
    let reader = io::BufReader::new(file);
    reader
        .lines()
        .filter_map(|line| {
            let line = line.expect("Failed to read line");
            let trimmed = line.trim();
            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
            // Ensure we have exactly 2 parts
            if parts.len() != 2 {
                tracer_println!(
                    "Warning: Invalid line format (expected 'string,number'): {}",
                    trimmed
                );
                return None;
            }
            match parts[1].parse::<usize>() {
                Ok(number) => Some((parts[0].to_string(), number)),
                Err(e) => {
                    tracer_println!("Warning: Failed to parse number '{}': {}", parts[1], e);
                    None
                }
            }
        })
        .collect()
}

pub fn pin_maps(skel: &mut PinMapsSkel) {
    let res = skel.maps.history.unpin("/sys/fs/bpf/history");

    match res {
        Ok(_) => {
            //tracer_println!("Successfully unpinned map")
        }
        Err(e) => tracer_println!("Error unpinning map: {}", e),
    }

    let res = skel
        .maps
        .network_information
        .unpin("/sys/fs/bpf/network_information");

    match res {
        Ok(_) => {
            //tracer_println!("Successfully unpinned map")
        }
        Err(e) => tracer_println!("Error unpinning map: {}", e),
    }

    let res = skel.maps.history_delays.unpin("/sys/fs/bpf/history_delays");

    match res {
        Ok(_) => {
            //tracer_println!("Successfully unpinned map")
        }
        Err(e) => tracer_println!("Error unpinning map: {}", e),
    }

    let res = skel
        .maps
        .event_counter_for_delays
        .unpin("/sys/fs/bpf/event_counter_for_delays");

    match res {
        Ok(_) => {
            //tracer_println!("Successfully unpinned map")
        }
        Err(e) => tracer_println!("Error unpinning map: {}", e),
    }

    let res = skel.maps.pid_tree.unpin("/sys/fs/bpf/pid_tree");

    match res {
        Ok(_) => {
            //tracer_println!("Successfully unpinned map")
        }
        Err(e) => tracer_println!("Error unpinning map: {}", e),
    }

    skel.maps
        .history
        .pin("/sys/fs/bpf/history")
        .expect("Failed to pin map");
    skel.maps
        .network_information
        .pin("/sys/fs/bpf/network_information")
        .expect("Failed to pin map");
    skel.maps
        .history_delays
        .pin("/sys/fs/bpf/history_delays")
        .expect("Failed to pin map");
    skel.maps
        .event_counter_for_delays
        .pin("/sys/fs/bpf/event_counter_for_delays")
        .expect("Failed to pin map");
    skel.maps
        .pid_tree
        .pin("/sys/fs/bpf/pid_tree")
        .expect("Failed to pin map");
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
        435 => String::from("clone3"),
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
        439 => String::from("faccessat2"),
        _ => format!("unknown_syscall_{}", syscall_id),
    }
}
