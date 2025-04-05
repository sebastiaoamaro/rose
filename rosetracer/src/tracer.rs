use crate::auxiliary::collect_events;
use crate::auxiliary::create_pid_tree;
use crate::auxiliary::write_to_file;
use crate::auxiliary::{
    self, collect_fd_map, collect_network_delays, collect_network_info, monitor_pid, pin_maps,
    start_xdp_in_container,
};
use anyhow::Result;
use auxiliary::pin_maps::PinMapsSkelBuilder;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::Link;
use libbpf_rs::UprobeOpts;
use libbpf_rs::{MapCore, MapFlags};
use nix::net::if_::if_nametoindex;
use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs::create_dir;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{mpsc, Arc};
use std::thread::{self, sleep, JoinHandle};
use std::time::Duration;
use xdp::XdpSkelBuilder;

mod tracer {
    include!(concat!(env!("OUT_DIR"), "/tracer.skel.rs"));
}

mod xdp {
    include!(concat!(env!("OUT_DIR"), "/xdp.skel.rs"));
}

use tracer::*;

pub fn run_tracing(
    mode: String,
    functions: Vec<String>,
    binary_path: String,
    nodes_info: String,
    network_device: String,
) -> Result<()> {
    auxiliary::bump_memlock_rlimit()?;
    //Init maps

    let skel_builder_maps = PinMapsSkelBuilder::default();

    let mut open_object_maps = MaybeUninit::uninit();
    let open_skel_maps = skel_builder_maps.open(&mut open_object_maps)?;

    let mut skel_maps = open_skel_maps.load()?;

    pin_maps(&mut skel_maps);

    //Init variables for tracing

    let mut hashmap_links: HashMap<i32, Vec<Link>> = HashMap::new();
    let mut hashmap_pid_to_node: HashMap<i32, String> = HashMap::new();
    let mut hashmap_node_to_pid: HashMap<String, i32> = HashMap::new();

    //Build the BPF program
    let skel_builder = TracerSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    let mut open_object_tracer = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object_tracer)?;

    let mut skel = open_skel.load()?;

    let _tracepoint_sys_enter = skel
        .progs
        .trace_sys_enter
        .attach_tracepoint("raw_syscalls", "sys_enter")
        .expect("Failed to attach sys_exit");

    let _tracepoint_sys_exit = skel
        .progs
        .trace_sys_exit
        .attach_tracepoint("raw_syscalls", "sys_exit")
        .expect("Failed to attach sys_exit");

    let _tracepoint_proc_start = skel
        .progs
        .handle_exec
        .attach_tracepoint("sched", "sched_process_exec")
        .expect("Failed to attach sched_process_exec");

    //Variable needs to be here so that program stays alive
    let _xdp_prog;

    if mode == "container" {
        trace_containers(
            nodes_info,
            &mut skel,
            &mut hashmap_pid_to_node,
            &mut hashmap_links,
            functions.clone(),
            binary_path,
        )
        .expect("Failed to trace containers");
    } else if mode == "container_controlled" {
        trace_containers_controlled(
            nodes_info.clone(),
            &mut skel,
            &mut hashmap_pid_to_node,
            &mut hashmap_node_to_pid,
            &mut hashmap_links,
            functions.clone(),
            binary_path,
        )
        .expect("Failed to trace containers controlled");

        // Attempt to delete the file
        match fs::remove_file(nodes_info.clone()) {
            Ok(_) => println!("File deleted successfully."),
            Err(e) => println!("Failed to delete the file: {}", e),
        }
    } else if mode == "process" {
        trace_processes(
            nodes_info,
            &mut skel,
            &mut hashmap_pid_to_node,
            &mut hashmap_links,
            functions.clone(),
            binary_path,
        )
        .expect("Failed to trace processes");

        let skel_builder = XdpSkelBuilder::default();

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
        let skel_builder = XdpSkelBuilder::default();

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
            &mut skel,
            &mut hashmap_pid_to_node,
            &mut hashmap_node_to_pid,
            &mut hashmap_links,
            functions.clone(),
            binary_path,
        )
        .expect("Failed to trace processes controlled");
    }

    create_pid_tree(&skel_maps.maps.pid_tree, &mut hashmap_pid_to_node);

    let mut filenames = collect_fd_map(&skel.maps.fd_to_name, &skel.maps.dup_map);

    collect_network_info(&skel_maps.maps.network_information);

    collect_network_delays(&skel_maps.maps.history_delays);

    collect_events(
        &skel.maps.history,
        functions.clone(),
        hashmap_pid_to_node,
        &mut filenames,
    );

    Ok(())
}

pub fn trace_processes(
    nodes_info: String,
    skel: &mut TracerSkel,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    mut hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<String>,
    binary_path: String,
) -> Result<()> {
    let mut join_handles = vec![];
    let mut tx_handles = vec![];

    // Specify the file path
    let path = nodes_info; // Change this to your file's path

    // Open the file
    let file: File = File::open(&path)?;

    // Create a buffered reader for efficient reading
    let reader = BufReader::new(file);

    // Iterate over each line
    for line in reader.lines() {
        let line = line?; // Handle any errors
        let parts: Vec<&str> = line.split(',').collect(); // Split by comma

        if parts.len() == 2 {
            let node_name = parts[0].trim(); // The string part (trim to remove extra spaces)
            let pid: i32 = match parts[1].trim().parse() {
                Ok(num) => num, // Parse the second part as an integer
                Err(_) => {
                    println!("Failed to parse integer on line: {}", line);
                    continue; // Skip if parsing fails
                }
            };

            let pid_vec = auxiliary::u32_to_u8_array_little_endian(pid);
            let one = auxiliary::u32_to_u8_array_little_endian(1);
            skel.maps.pid_tree.update(&pid_vec, &one, MapFlags::ANY)?;

            hashmap_pid_to_node.insert(pid, node_name.to_string().clone());

            let (tx, rx) = mpsc::channel();
            tx_handles.push(tx);

            start_tracing_process(
                pid,
                node_name.to_string(),
                &mut hashmap_links,
                functions.clone(),
                binary_path.clone(),
                skel,
                rx,
                &mut join_handles,
            );
        } else {
            println!("Incorrect format on line: {}", line);
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

    Ok(())
}
pub fn start_tracing_process(
    pid: i32,
    container_name: String,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<String>,
    binary_path: String,
    skel: &mut TracerSkel,
    rx: Receiver<()>,
    join_handles: &mut Vec<JoinHandle<()>>,
) {
    println!(
        "Started tracing for pid {} with node_name {}",
        pid, container_name
    );

    hashmap_links.insert(pid, vec![]);

    let handle = thread::spawn(move || {
        monitor_pid(pid, rx).expect("Monitoring failed");
    });

    join_handles.push(handle);

    for (index_function, function) in functions.clone().iter().enumerate() {
        let opts = UprobeOpts {
            cookie: index_function as u64,
            retprobe: false,
            func_name: function.clone(),
            ..Default::default()
        };

        let uprobe =
            skel.progs
                .handle_uprobe
                .attach_uprobe_with_opts(pid, binary_path.clone(), 0, opts);

        match uprobe {
            Ok(uprobe_injected) => {
                hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                println!("Injected in pos {} in pid {}", index_function, pid);
            }
            Err(e) => {
                println!("Failed:{}, err:{}", function.clone(), e);
                continue;
            }
        }
    }
}

pub fn trace_containers(
    nodes_info: String,
    skel: &mut TracerSkel,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    mut hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<String>,
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
                    println!("Failed to parse integer on line: {}", line);
                    continue;
                }
            };
            let veth = parts[2].trim();

            let veth_index = if_nametoindex(veth).map_err(|e| e.to_string()).unwrap();

            let pid_vec = auxiliary::u32_to_u8_array_little_endian(pid);
            let one = auxiliary::u32_to_u8_array_little_endian(1);
            skel.maps.pid_tree.update(&pid_vec, &one, MapFlags::ANY)?;

            hashmap_pid_to_node.insert(pid, node_name.to_string().clone());

            let (tx, rx) = mpsc::channel();
            tx_handles.push(tx);
            start_tracing_container(
                pid,
                node_name.to_string(),
                &mut hashmap_links,
                functions.clone(),
                binary_path.clone(),
                skel,
                rx,
                &mut join_handles,
            );
            start_xdp_in_container(pid, (veth_index) as i32);
        } else {
            println!("Incorrect format on line: {}", line);
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
            Ok(_) => println!("Sent successfully"),
            Err(e) => println!("Error sending: {}", e),
        }
    }

    for handle in join_handles {
        let result = handle.join();

        match result {
            Ok(_) => println!("Thread finished successfully"),
            Err(_e) => println!("Thread finished with an error"),
        }
    }

    Ok(())
}

pub fn start_tracing_container(
    pid: i32,
    container_name: String,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<String>,
    binary_path: String,
    skel: &mut TracerSkel,
    rx: Receiver<()>,
    join_handles: &mut Vec<JoinHandle<()>>,
) {
    println!(
        "Started tracing for pid {} with node_name {}",
        pid, container_name
    );

    //let _tracepoint_sys_enter = skel.progs.trace_sys_enter.attach_tracepoint("raw_syscalls", "sys_enter").expect("Failed to attach sys_enter");
    hashmap_links.insert(pid, vec![]);

    let handle = thread::spawn(move || {
        monitor_pid(pid, rx).expect("Monitoring failed");
    });

    join_handles.push(handle);

    let container_location = auxiliary::get_overlay2_location(&container_name).unwrap();

    let binary_location = format!("{}{}", container_location, binary_path);

    for (index_function, function) in functions.clone().iter().enumerate() {
        let opts = UprobeOpts {
            cookie: index_function as u64,
            retprobe: false,
            func_name: function.clone(),
            ..Default::default()
        };

        //with -1 no overhead, but the handle will be called multiple times, specify pid
        let uprobe =
            skel.progs
                .handle_uprobe
                .attach_uprobe_with_opts(pid, binary_location.clone(), 0, opts);

        match uprobe {
            Ok(uprobe_injected) => {
                hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                //println!("Injected in pos {} in pid {}",index_function,pid);
            }
            Err(e) => {
                println!("Failed:{}, err:{}", function.clone(), e);
                continue;
            }
        }
    }
}

pub fn trace_containers_controlled(
    nodes_info: String,
    skel: &mut TracerSkel,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    hashmap_node_to_pid: &mut HashMap<String, i32>,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<String>,
    binary_path: String,
) -> Result<()> {
    let mut join_handles = vec![];
    let mut xdp_pids = vec![];
    let mut tx_handles = vec![];
    //Loop read from a pipe to get pid+container
    if Path::new(&nodes_info).exists() {
        println!("Opening FIFO for reading...");

        let file = File::open(nodes_info.clone()).unwrap();
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;

            println!("Received:{}", line);

            if line == "finished" {
                break;
            }

            let parts: Vec<&str> = line.split(',').collect();

            let node_name = parts[0].to_string();

            let container_pid: i32 = parts[1].parse().unwrap();

            let pid: i32 = parts[2].parse().unwrap();

            let if_index: i32 = parts[3].parse().unwrap();

            let pid_vec = auxiliary::u32_to_u8_array_little_endian(pid);
            let one = auxiliary::u32_to_u8_array_little_endian(1);

            skel.maps.pid_tree.update(&pid_vec, &one, MapFlags::ANY)?;

            let node_already_traced = hashmap_node_to_pid.get(&node_name.clone()).is_some();

            hashmap_pid_to_node.insert(pid, node_name.clone());
            hashmap_node_to_pid.insert(node_name.clone(), pid);
            let (tx, rx) = mpsc::channel();
            tx_handles.push(tx);
            start_tracing_container(
                pid,
                node_name.clone(),
                hashmap_links,
                functions.clone(),
                binary_path.clone(),
                skel,
                rx,
                &mut join_handles,
            );

            if !node_already_traced {
                if if_index != 0 {
                    let pid = start_xdp_in_container(container_pid, if_index);
                    xdp_pids.push(pid);
                }
            }
        }
    } else {
        println!("FIFO does not exist.");
    }

    for tx in tx_handles {
        let send_res = tx.send(());

        match send_res {
            Ok(_) => println!("Sent successfully"),
            Err(e) => println!("Error sending: {}", e),
        }
    }

    for handle in join_handles {
        let result = handle.join();

        match result {
            Ok(_) => println!("Thread finished successfully"),
            Err(_e) => println!("Thread finished with an error"),
        }
    }

    for pid in xdp_pids {
        let pid = Pid::from_raw(pid as i32); // Convert the PID to a Pid type
        kill(pid, Signal::SIGKILL).expect("Failed to kill xdp_pid");
    }
    println!("Finished tracing containers");

    Ok(())
}

pub fn trace_processes_controlled(
    nodes_info: String,
    skel: &mut TracerSkel,
    hashmap_pid_to_node: &mut HashMap<i32, String>,
    hashmap_node_to_pid: &mut HashMap<String, i32>,
    hashmap_links: &mut HashMap<i32, Vec<Link>>,
    functions: Vec<String>,
    binary_path: String,
) -> Result<()> {
    let mut join_handles = vec![];
    let mut tx_handles = vec![];
    //Loop read from a pipe to get pid+container
    if Path::new(&nodes_info).exists() {
        println!("Opening FIFO for reading...");

        // Open the FIFO for reading in blocking mode
        let file = File::open(nodes_info.clone()).unwrap();

        println!("FIFO open in read_mode");
        let reader = BufReader::new(file);

        println!("Reader started");
        // Step 2: Read lines from the FIFO and print them
        for line in reader.lines() {
            let line = line?;

            println!("Received:{}", line);

            if line == "finished" {
                break;
            }

            let parts: Vec<&str> = line.split(',').collect();

            let node_name = parts[0].to_string();

            let _container_pid: i32 = parts[1].parse().unwrap();

            let pid: i32 = parts[2].parse().unwrap();

            let _if_index: i32 = parts[3].parse().unwrap();

            let pid_vec = auxiliary::u32_to_u8_array_little_endian(pid);

            let one = auxiliary::u32_to_u8_array_little_endian(1);

            skel.maps.pid_tree.update(&pid_vec, &one, MapFlags::ANY)?;

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
        }
    } else {
        println!("FIFO does not exist.");
    }

    for tx in tx_handles {
        let send_res = tx.send(());

        match send_res {
            Ok(_) => println!("Sent successfully"),
            Err(e) => println!("Error sending: {}", e),
        }
    }

    for handle in join_handles {
        let result = handle.join();

        match result {
            Ok(_) => println!("Thread finished successfully"),
            Err(_e) => println!("Thread finished with an error"),
        }
    }

    Ok(())
}
