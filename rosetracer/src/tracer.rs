use anyhow::Result;
use libbpf_rs::Link;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::UprobeOpts;
use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use pin_maps::PinMapsSkelBuilder;
use crate::auxiliary;
use crate::auxiliary::collect_functions_called_array;
use crate::auxiliary::collect_network_delays;
use crate::auxiliary::collect_network_info;
use crate::auxiliary::monitor_pid;
use crate::auxiliary::start_xdp_in_container;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::thread;
use std::thread::JoinHandle;
mod tracer {
    include!(concat!(env!("OUT_DIR"), "/tracer.skel.rs"));
}

mod pin_maps{
    include!(concat!(env!("OUT_DIR"), "/pin_maps.skel.rs"));
}
use tracer::*;

pub fn run_tracing(
    functions: Vec<String>,
    binary_path:String,
    collect_process_info_pipe:String
) -> Result<()>{

    auxiliary::bump_memlock_rlimit()?; 
    
    //Init maps

    let skel_builder_maps = PinMapsSkelBuilder::default();

    let mut open_object_maps = MaybeUninit::uninit();
    let open_skel_maps = skel_builder_maps.open(&mut open_object_maps)?;

    let mut skel_maps = open_skel_maps.load()?;

    let res = skel_maps.maps.history.unpin("/sys/fs/bpf/history");

    match res {
        Ok(_) => println!("Successfully unpinned map"),
        Err(e) => println!("Error unpinning map: {}", e),
    }
    let res = skel_maps.maps.uprobes_counters.unpin("/sys/fs/bpf/uprobes_counters");

    match res {
        Ok(_) => println!("Successfully unpinned map"),
        Err(e) => println!("Error unpinning map: {}", e),
    }

    let res = skel_maps.maps.network_information.unpin("/sys/fs/bpf/network_information");

    match res {
        Ok(_) => println!("Successfully unpinned map"),
        Err(e) => println!("Error unpinning map: {}", e),
    }

    let res = skel_maps.maps.history_delays.unpin("/sys/fs/bpf/history_delays");

    match res {
        Ok(_) => println!("Successfully unpinned map"),
        Err(e) => println!("Error unpinning map: {}", e),
    }

    let res = skel_maps.maps.event_counter_for_delays.unpin("/sys/fs/bpf/event_counter_for_delays");

    match res {
        Ok(_) => println!("Successfully unpinned map"),
        Err(e) => println!("Error unpinning map: {}", e),
    }

    skel_maps.maps.history.pin("/sys/fs/bpf/history").expect("Failed to pin map");
    skel_maps.maps.uprobes_counters.pin("/sys/fs/bpf/uprobes_counters").expect("Failed to pin map");
    skel_maps.maps.network_information.pin("/sys/fs/bpf/network_information").expect("Failed to pin map");
    skel_maps.maps.history_delays.pin("/sys/fs/bpf/history_delays").expect("Failed to pin map");
    skel_maps.maps.event_counter_for_delays.pin("/sys/fs/bpf/event_counter_for_delays").expect("Failed to pin map");

    //Init variables for tracing

    let mut hashmap_links:HashMap<i32,Vec<Link>> = HashMap::new();
    let mut hashmap_pid_to_node:HashMap<i32,String> = HashMap::new();
    let mut hashmap_node_to_pid:HashMap<String,i32> = HashMap::new();

    //Build the BPF program
    let skel_builder = TracerSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    let mut open_object_tracer = MaybeUninit::uninit();
    
    let open_skel = skel_builder.open(&mut open_object_tracer)?;

    let mut skel = open_skel.load()?;

    let _tracepoint_sys_enter = skel.progs.trace_sys_enter.attach_tracepoint("raw_syscalls", "sys_enter").expect("Failed to attach sys_exit");

    let _tracepoint_sys_exit = skel.progs.trace_sys_exit.attach_tracepoint("raw_syscalls", "sys_exit").expect("Failed to attach sys_exit");
    //let _connect_enter = skel.progs.trace_connect_entry.attach_tracepoint("syscalls", "sys_enter_connect").expect("Failed to attach connect");


    //Create history file
    let res = File::create_new("/tmp/history.txt");

    if res.is_err(){
         println!("File already exists");
    }

    let mut join_handles = vec![];

    let mut tx_handles = vec![];   

    let mut xdp_pids = vec![];

    //Loop read from a pipe to get pid+container
    if Path::new(&collect_process_info_pipe).exists() {
        println!("Opening FIFO for reading...");

        // Open the FIFO for reading in blocking mode
        let file = File::open(collect_process_info_pipe.clone()).unwrap();

        println!("FIFO open in read_mode");
        let reader = BufReader::new(file);

        println!("Reader started");
        // Step 2: Read lines from the FIFO and print them
        for line in reader.lines() {
            let line = line?;
            
            println!("Received:{}", line);

            if line == "finished"{
                break;
            }

            let parts: Vec<&str> = line.split(',').collect();

            let node_name = parts[0].to_string();

            let container_pid:i32 = parts[1].parse().unwrap();

            let pid:i32 = parts[2].parse().unwrap();

            let if_index:i32 = parts[3].parse().unwrap();

            let pid_vec = auxiliary::u32_to_u8_array_little_endian(pid);

            skel.maps
            .pids
            .update(&pid_vec, &pid_vec, MapFlags::ANY)?;

            let node_already_traced = hashmap_node_to_pid.get(&node_name.clone()).is_some();
            
                hashmap_pid_to_node.insert(pid, node_name.clone());
                hashmap_node_to_pid.insert(node_name.clone(), pid);
                let (tx, rx) = mpsc::channel();
                tx_handles.push(tx);
                start_tracing(pid, node_name.clone(),container_pid,if_index, &mut hashmap_links, functions.clone(), binary_path.clone(), &mut skel,rx,&mut join_handles);                
            
            if !node_already_traced{
                if if_index != 0 {
                    let pid = start_xdp_in_container(container_pid, if_index);
                    xdp_pids.push(pid);
                }
            }

        }
    } else {
        println!("FIFO does not exist.");
    }

    for tx in tx_handles{
        tx.send(()).unwrap();
    }

    for handle in join_handles{
        handle.join().unwrap();
    }

    for pid in xdp_pids{
        let pid = Pid::from_raw(pid as i32); // Convert the PID to a Pid type
        println!("Killing xdp_pid: {}", pid);
        kill(pid, Signal::SIGKILL).expect("Failed to kill xdp_pid"); 
    }
    

    collect_network_info(&skel_maps.maps.network_information);

    collect_network_delays(&skel_maps.maps.history_delays);

    collect_functions_called_array(&skel.maps.history,functions.clone(),hashmap_pid_to_node);


     // Attempt to delete the file
     match fs::remove_file(collect_process_info_pipe.clone()) {
        Ok(_) => println!("File deleted successfully."),
        Err(e) => println!("Failed to delete the file: {}", e),
    }


    println!("Done tracing");

    Ok(())
}

pub fn start_tracing(pid:i32,container_name:String,container_pid:i32,if_index:i32,hashmap_links:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String,skel:& mut TracerSkel, rx:Receiver<()>,join_handles: &mut Vec<JoinHandle<()>>) {

    println!("Started tracing for pid {} with node_name {}",pid,container_name);
    hashmap_links.insert(pid, vec![]);

    let handle = thread::spawn(move || {
        monitor_pid(pid, rx).expect("Monitoring failed");
    });

    join_handles.push(handle);

    // let xdp_prog = skel.progs.xdp_pass.attach_xdp(if_index-1).expect("Failed to attach xdp");
    // hashmap_links.get_mut(&pid).unwrap().push(xdp_prog);
    //hashmap_links_ret.insert(*pid, vec![0;512]);
    let container_location = auxiliary::get_overlay2_location(&container_name).unwrap();

    let binary_location = format!("{}{}", container_location, binary_path);


    for (index_function, function) in functions.clone().iter().enumerate(){
        let opts = UprobeOpts{cookie:index_function as u64,retprobe:false,func_name:function.clone(),..Default::default()};

        let uprobe = skel.progs.handle_uprobe.attach_uprobe_with_opts(pid as i32, binary_location.clone(), 0, opts);

        match uprobe{
            Ok(uprobe_injected) => {
                hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                //println!("Injected in pos {} in pid {}",index_function,pid);
            }
            Err(e) => {
                println!("Failed:{}",function.clone());
                continue;
            }
        }
    }

    
}