use anyhow::Result;
use libbpf_rs::Link;
use libbpf_rs::{MapCore, MapFlags};
use libbpf_rs::UprobeOpts;
use pin_maps::PinMapsSkelBuilder;
use crate::auxiliary::{self, get_device_index, start_xdp_in_container};
use crate::auxiliary::collect_functions_called_array;
use crate::auxiliary::write_to_file;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use nix::net::if_::if_nametoindex;
use xdp::XdpSkelBuilder;

mod tracer {
    include!(concat!(env!("OUT_DIR"), "/tracer.skel.rs"));
}

mod pin_maps{
    include!(concat!(env!("OUT_DIR"), "/pin_maps.skel.rs"));
}

mod xdp {
  include!(concat!(env!("OUT_DIR"), "/xdp.skel.rs"));
}

use tracer::*;

pub fn run_tracing(
    mode:String,
    functions: Vec<String>,
    binary_path:String,
    node_and_pid:String,
    network_interface:String,
) -> Result<()>{ 
    
    auxiliary::bump_memlock_rlimit()?;
    //Init maps

    let skel_builder_maps = PinMapsSkelBuilder::default();

    let mut open_object_maps = MaybeUninit::uninit();
    let open_skel_maps = skel_builder_maps.open(&mut open_object_maps)?;

    let mut skel_maps = open_skel_maps.load()?;
    //Init variables for tracing

    let mut hashmap_links:HashMap<i32,Vec<Link>> = HashMap::new();
    let mut hashmap_pid_to_node:HashMap<i32,String> = HashMap::new();

    //Build the BPF program
    let skel_builder = TracerSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    let mut open_object_tracer = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object_tracer)?;

    let mut skel = open_skel.load()?;

    let _tracepoint_sys_exit = skel.progs.trace_sys_exit.attach_tracepoint("raw_syscalls", "sys_exit").expect("Failed to attach sys_exit");

    //Variable needs to be here so that program stays alive
    let xdp_prog;

    if mode == "container"{
        trace_containers(node_and_pid, &mut skel,&mut hashmap_pid_to_node, &mut hashmap_links, functions.clone(), binary_path).expect("Failed to trace containers");
    }else{
        trace_processes(node_and_pid, &mut skel,&mut hashmap_pid_to_node, &mut hashmap_links, functions.clone(), binary_path).expect("Failed to trace processes");
        let skel_builder = XdpSkelBuilder::default();

        let mut open_object_tracer = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut open_object_tracer)?;
      
        let skel = open_skel.load()?;
        let if_index = get_device_index(&network_interface).unwrap();
        xdp_prog = skel.progs.xdp_pass.attach_xdp((if_index-1) as i32).expect("Failed to attach xdp");
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

    collect_functions_called_array(&skel.maps.history,functions.clone(),hashmap_pid_to_node);

    skel_maps.maps.history.unpin("/sys/fs/bpf/history").expect("Failed to unpin \n");
    skel_maps.maps.uprobes_counters.unpin("/sys/fs/bpf/uprobes_counters").expect("Failed to unpin \n");
    
    println!("Done tracing");

    Ok(())

}



pub fn trace_processes(node_and_pid:String,skel:&mut TracerSkel,hashmap_pid_to_node:&mut HashMap<i32,String>,mut hashmap_links:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String)-> Result<()> {
    // Specify the file path
    let path = node_and_pid;  // Change this to your file's path

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
            skel.maps
                .pids
                .update(&pid_vec, &pid_vec, MapFlags::ANY)?;

            hashmap_pid_to_node.insert(pid, node_name.to_string().clone());

            start_tracing_process(pid, node_name.to_string(),&mut hashmap_links, functions.clone(), binary_path.clone(),skel);
        } else {
            println!("Incorrect format on line: {}", line);
        }
    }
    Ok(())
}
pub fn start_tracing_process(pid:i32,container_name:String,hashmap_links:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String,skel:&mut TracerSkel){
   
    println!("Started tracing for pid {} with node_name {}",pid,container_name);

    hashmap_links.insert(pid, vec![]);

    for (index_function, function) in functions.clone().iter().enumerate(){
        let opts = UprobeOpts{cookie:index_function as u64,retprobe:false,func_name:function.clone(),..Default::default()};

        let uprobe = skel.progs.handle_uprobe.attach_uprobe_with_opts(-1, binary_path.clone(), 0, opts);

        match uprobe{
            Ok(uprobe_injected) => {
                hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                println!("Injected in pos {} in pid {}",index_function,pid);
            }
            Err(e) => {
                println!("Failed:{}, err:{}",function.clone(),e);
                continue;
            }
        }

    }
}

pub fn trace_containers(node_and_pid:String,skel:&mut TracerSkel,hashmap_pid_to_node:&mut HashMap<i32,String>,mut hashmap_links:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String)-> Result<()> {
    // Specify the file path
    let path = node_and_pid;  // Change this to your file's path

    // Open the file
    let file: File = File::open(&path)?;
    
    // Create a buffered reader for efficient reading
    let reader = BufReader::new(file);

    // Iterate over each line
    for line in reader.lines() {
        let line = line?; // Handle any errors
        let parts: Vec<&str> = line.split(',').collect(); // Split by comma

        if parts.len() == 3 {
            let node_name = parts[0].trim(); // The string part (trim to remove extra spaces)
            let pid: i32 = match parts[1].trim().parse() {
                Ok(num) => num, // Parse the second part as an integer
                Err(_) => {
                    println!("Failed to parse integer on line: {}", line);
                    continue; // Skip if parsing fails
                }
            };
            let veth = parts[2].trim();

            let veth_index = if_nametoindex(veth).map_err(|e| e.to_string()).unwrap();

            let pid_vec = auxiliary::u32_to_u8_array_little_endian(pid);
            skel.maps
                .pids
                .update(&pid_vec, &pid_vec, MapFlags::ANY)?;

            hashmap_pid_to_node.insert(pid, node_name.to_string().clone());

            start_tracing_container(pid, node_name.to_string(),veth_index, &mut hashmap_links, functions.clone(), binary_path.clone(),skel);
        } else {
            println!("Incorrect format on line: {}", line);
        }
    }
    Ok(())
}


pub fn start_tracing_container(pid:i32,container_name:String,if_index:u32,hashmap_links:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String,skel:&mut TracerSkel){
   
    println!("Started tracing for pid {} with node_name {}",pid,container_name);

    //let _tracepoint_sys_enter = skel.progs.trace_sys_enter.attach_tracepoint("raw_syscalls", "sys_enter").expect("Failed to attach sys_enter");    
    hashmap_links.insert(pid, vec![]);

    start_xdp_in_container(pid, (if_index-1) as i32);
    // let xdp_prog = skel.progs.xdp_pass.attach_xdp(veth_index as i32).expect("Failed to attach xdp");
    // hashmap_links.get_mut(&pid).unwrap().push(xdp_prog);

    let container_location = auxiliary::get_overlay2_location(&container_name).unwrap();

    let binary_location = format!("{}{}", container_location, binary_path);

    for (index_function, function) in functions.clone().iter().enumerate(){
        let opts = UprobeOpts{cookie:index_function as u64,retprobe:false,func_name:function.clone(),..Default::default()};

        let uprobe = skel.progs.handle_uprobe.attach_uprobe_with_opts(-1, binary_location.clone(), 0, opts);

        match uprobe{
            Ok(uprobe_injected) => {
                hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                println!("Injected in pos {} in pid {}",index_function,pid);
            }
            Err(e) => {
                println!("Failed:{}, err:{}",function.clone(),e);
                continue;
            }
        }

    }
}

