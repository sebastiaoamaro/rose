use anyhow::Result;
use libbpf_rs::Link;
use libbpf_rs::MapFlags;
use libbpf_rs::UprobeOpts;
use crate::auxiliary;
use crate::auxiliary::key;
use crate::auxiliary::write_to_file;
use crate::auxiliary::vec_to_i32;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use core::time::Duration;
use std::thread::sleep;

mod tracer {
    include!(concat!(env!("OUT_DIR"), "/tracer.skel.rs"));
}
use tracer::*;

pub fn run_tracing(
    functions: Vec<String>,
    binary_path:String,
    collect_process_info_pipe:String
) -> Result<()>{ 

    
    //Init variables for tracing

    let mut hashmap_uprobes:HashMap<i32,Vec<Link>> = HashMap::new();

    //Build the BPF program
    let mut skel_builder = TracerSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    auxiliary::bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    //open_skel.rodata_mut().pid_counter = pid_count as i32;
    //open_skel.rodata().pid_counter = pid_count as i32;

    let mut skel = open_skel.load()?;

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

            let pid:i32 = parts[1].parse().unwrap();

            start_tracing(pid, node_name, &mut hashmap_uprobes, functions.clone(), binary_path.clone(), &mut skel);

        }
    } else {
        println!("FIFO does not exist.");
    }

    println!("Done tracing");


    // for (index,pid) in pids.iter().enumerate(){
    //     let pid_vec = u32_to_u8_array_little_endian(*pid);
    //     skel.maps_mut().pids().update(&pid_vec, &pid_vec, MapFlags::ANY)?;
    // } 
    
    

    // let mut uprobes:Vec<Link> = vec![];

    // let mut hashmap_uprobes:HashMap<i32,Vec<Link>> = HashMap::new();

    // let mut uprobes_counter:Vec<i32> = vec![0;512];


    // //If we are tracing containers we need to find the correct file

    println!("Done tracing");

    collect_functions_called_array(skel.maps().called_functions());


    Ok(())
}

fn process_uprobes_array_map(uprobes_array:&libbpf_rs::Map,uprobes_counter:&mut Vec<i32>,functions:Vec<String>) -> Vec<i32>{

    let keys = uprobes_array.keys();

    let mut probes_detected:Vec<i32> = vec![];

    for key in keys {
        let result = uprobes_array.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {

                let cookie = vec_to_i32(key);

                let value_vec = result.unwrap().clone();

                let value = vec_to_i32(value_vec);
                
                if (value) > 0{
                    probes_detected.push(cookie);
                }
                
                uprobes_counter[cookie as usize] = value;
            }
            Err(e) => {
                println!("Err: {:?}", e);
            }
        }
    }
    
    return probes_detected;


}
fn collect_functions_called_array(called_functions: &libbpf_rs::Map){
    let keys = called_functions.keys();

    //Use later
    let mut functions: Vec<&key> = vec![];
    for key in keys {
        let result = called_functions.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let key = result.unwrap().clone();

                unsafe {
                    let key: *const key = key.as_ptr() as *const key;
                    let readable_key: &key = &*key;

                    //let text = buffer_to_string(&readable_io_op.buffer);
                    
                    if(readable_key.pid == 0){
                        continue;
                    }
                    functions.push(readable_key);

                    println!("Pid: {}, Tid: {}, Cookie:{}",readable_key.pid,readable_key.tid,readable_key.cookie);
                    
                }
            }
            Err(e) => {
                println!("Err: {:?}", e);
            }
        }
    }



}

pub fn start_tracing(pid:i32,container_name:String,hashmap_uprobes:&mut HashMap<i32,Vec<Link>>,functions: Vec<String>,binary_path:String,skel:& mut TracerSkel){

    
    println!("Started tracing for pid {} with node_name {}",pid,container_name);


    let _tracepoint_sys_enter = skel.progs_mut().trace_sys_enter().attach_tracepoint("raw_syscalls", "sys_enter").expect("Failed to attach sys_enter");

    let _tracepoint_sys_exit = skel.progs_mut().trace_sys_exit().attach_tracepoint("raw_syscalls", "sys_exit").expect("Failed to attach sys_exit");

    hashmap_uprobes.insert(pid, vec![]);
    //hashmap_uprobes_ret.insert(*pid, vec![0;512]);

    let container_location = auxiliary::get_overlay2_location(&container_name).unwrap();

    let binary_location = format!("{}{}", container_location, binary_path);


    for (index_function, function) in functions.clone().iter().enumerate(){
        let opts = UprobeOpts{cookie:index_function as u64,retprobe:false,func_name:function.clone(),..Default::default()};

        let uprobe = skel.progs_mut().handle_uprobe().attach_uprobe_with_opts(pid as i32, binary_location.clone(), 0, opts);

        match uprobe{
            Ok(uprobe_injected) => {
                hashmap_uprobes.get_mut(&pid).unwrap().push(uprobe_injected);
                println!("Injected in pos {} in pid {}",index_function,pid);
            }
            Err(e) => {
                println!("Failed:{}",function.clone());
                continue;
            }
        }
    }
}