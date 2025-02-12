use anyhow::Result;
use libbpf_rs::Link;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::UprobeOpts;
use pin_maps::PinMapsSkelBuilder;
use crate::auxiliary;
use crate::auxiliary::process_uprobes_array_map;
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
use auxiliary::remove_duplicates;

mod tracer {
    include!(concat!(env!("OUT_DIR"), "/tracer.skel.rs"));
}

mod pin_maps{
    include!(concat!(env!("OUT_DIR"), "/pin_maps.skel.rs"));
}
use tracer::*;

pub fn run_tracing(
    mode:String,
    functions: Vec<String>,
    binary_path:String,
    node_and_pid:String
) -> Result<()>{ 
    
    //Init maps

    let skel_builder_maps = PinMapsSkelBuilder::default();

    let mut open_object_maps = MaybeUninit::uninit();
    let open_skel_maps = skel_builder_maps.open(&mut open_object_maps)?;

    let mut skel_maps = open_skel_maps.load()?;
    //Init variables for tracing

    let mut hashmap_uprobes:HashMap<i32,Vec<Link>> = HashMap::new();
    let mut hashmap_pid_to_node:HashMap<i32,String> = HashMap::new();

    //Build the BPF program
    let skel_builder = TracerSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    let mut open_object_tracer = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object_tracer)?;

    let mut skel = open_skel.load()?;

    let mut unattachable_probes = vec![];

    if mode == "container"{
        trace_containers(node_and_pid.clone(),&mut skel,&mut hashmap_pid_to_node,
        &mut hashmap_uprobes,functions.clone(),binary_path.clone(),&mut unattachable_probes).expect("Error occurrend tracing containers");
    }else{
        trace_processes(node_and_pid.clone(),&mut skel,&mut hashmap_pid_to_node,
        &mut hashmap_uprobes,functions.clone(),binary_path.clone(),&mut unattachable_probes).expect("Error occurrend tracing processes");
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

    process_uprobes_array_map(&skel.maps.uprobes_counters);

    let probes_indexes_to_remove = remove_duplicates(unattachable_probes);


    write_to_file("/tmp/uprobe_stats.txt".to_string(), format!("{}\n","probes_to_remove:")).expect("Failed to write to stats file");


    for probe_idx in probes_indexes_to_remove{
        write_to_file("/tmp/uprobe_stats.txt".to_string(), format!("{}\n",functions.get(probe_idx as usize).unwrap())).expect("Failed to write to stats file");
    }


    skel_maps.maps.history.unpin("/sys/fs/bpf/history").expect("Failed to unpin \n");
    skel_maps.maps.uprobes_counters.unpin("/sys/fs/bpf/uprobes_counters").expect("Failed to unpin \n");

    println!("Done tracing");

    Ok(())
}

pub fn trace_containers(node_and_pid:String,skel:&mut TracerSkel,hashmap_pid_to_node:&mut HashMap<i32,String>,
    mut hashmap_links:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String,unattachable_probes:&mut Vec<u64>)-> Result<()>{

    let path = node_and_pid;  // Change this to your file's path

    let file = File::open(&path).expect("Failed to open file \n");
    
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(',').collect();

        if parts.len() == 2 {
            let node_name = parts[0].trim();
            let pid: i32 = match parts[1].trim().parse() {
                Ok(num) => num,
                Err(_) => {
                    println!("Failed to parse integer on line: {}", line);
                    continue;
                }
            };
            let pid_vec = auxiliary::u32_to_u8_array_little_endian(pid);

            skel.maps
            .pids
            .update(&pid_vec, &pid_vec, MapFlags::ANY)?;

            hashmap_pid_to_node.insert(pid, node_name.to_string().clone());

            start_tracing_container(pid, node_name.to_string(), &mut hashmap_links, functions.clone(), binary_path.clone(), skel,unattachable_probes);
        } else {
            println!("Incorrect format on line: {}", line);
        }
    }

    Ok(())


}

pub fn trace_processes(node_and_pid:String,skel:&mut TracerSkel,hashmap_pid_to_node:&mut HashMap<i32,String>,
    mut hashmap_links:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String,unattachable_probes:&mut Vec<u64>)-> Result<()>{
        let path = node_and_pid;  // Change this to your file's path

        let file = File::open(&path).expect("Failed to open file \n");
        
        let reader = BufReader::new(file);
    
        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split(',').collect();
    
            if parts.len() == 2 {
                let node_name = parts[0].trim();
                let pid: i32 = match parts[1].trim().parse() {
                    Ok(num) => num,
                    Err(_) => {
                        println!("Failed to parse integer on line: {}", line);
                        continue;
                    }
                };
                let pid_vec = auxiliary::u32_to_u8_array_little_endian(pid);
    
                skel.maps
                .pids
                .update(&pid_vec, &pid_vec, MapFlags::ANY)?;

                hashmap_pid_to_node.insert(pid, node_name.to_string().clone());
    
                start_tracing_process(pid, node_name.to_string(), &mut hashmap_links, functions.clone(), binary_path.clone(), skel,unattachable_probes);
            } else {
                println!("Incorrect format on line: {}", line);
            }
        }
        Ok(())
}

pub fn start_tracing_process(pid:i32,container_name:String,hashmap_uprobes:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String,skel:& mut TracerSkel,unattachable_probes:&mut Vec<u64>){

    
    println!("Started tracing for pid {} with node_name {}",pid,container_name);

    hashmap_uprobes.insert(pid, vec![]);
    //hashmap_uprobes_ret.insert(*pid, vec![0;512]);


    for (index_function, function) in functions.clone().iter().enumerate(){
        let opts = UprobeOpts{cookie:index_function as u64,retprobe:false,func_name:function.clone(),..Default::default()};

        let uprobe = skel.progs.handle_uprobe.attach_uprobe_with_opts(pid as i32, binary_path.clone(), 0, opts);

        match uprobe{
            Ok(uprobe_injected) => {
                hashmap_uprobes.get_mut(&pid).unwrap().push(uprobe_injected);
                //println!("Injected in pos {} in pid {}",index_function,pid);
            }
            Err(e) => {
                unattachable_probes.push(index_function as u64);
                println!("Failed:{} with err {}",function.clone(),e);
                continue;
            }
        }
    }
}




pub fn start_tracing_container(pid:i32,container_name:String,hashmap_uprobes:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String,skel:& mut TracerSkel,unattachable_probes:&mut Vec<u64>){

    
    println!("Started tracing for pid {} with node_name {}",pid,container_name);

    hashmap_uprobes.insert(pid, vec![]);
    //hashmap_uprobes_ret.insert(*pid, vec![0;512]);

    let container_location = auxiliary::get_overlay2_location(&container_name).unwrap();

    let binary_location = format!("{}{}", container_location, binary_path);


    for (index_function, function) in functions.clone().iter().enumerate(){
        let opts = UprobeOpts{cookie:index_function as u64,retprobe:false,func_name:function.clone(),..Default::default()};

        let uprobe = skel.progs.handle_uprobe.attach_uprobe_with_opts(pid as i32, binary_location.clone(), 0, opts);

        match uprobe{
            Ok(uprobe_injected) => {
                hashmap_uprobes.get_mut(&pid).unwrap().push(uprobe_injected);
                //println!("Injected in pos {} in pid {}",index_function,pid);
            }
            Err(e) => {
                unattachable_probes.push(index_function as u64);
                println!("Failed:{} with err {}",function.clone(),e);
                continue;
            }
        }
    }
}