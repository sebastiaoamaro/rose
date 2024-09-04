use anyhow::Result;
use libbpf_rs::Link;
use libbpf_rs::MapFlags;
use libbpf_rs::UprobeOpts;
use crate::auxiliary;
use crate::auxiliary::collect_trace;
use crate::auxiliary::collect_uprobe_stats;
use crate::auxiliary::read_names_from_file;
use crate::auxiliary::u32_to_u8_array_little_endian;
use crate::auxiliary::write_to_file;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use core::time::Duration;
use std::thread::sleep;

mod tracer {
    include!(concat!(env!("OUT_DIR"), "/tracer.skel.rs"));
}
use tracer::*;

pub fn run_tracing(
    pids: Vec<u32>,
    pid_count: usize,
    containers: Vec<String>,
    functions: Vec<String>,
    binary_path:String
) -> Result<()>{ 

    //Build the BPF program
    let mut skel_builder = TracerSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    auxiliary::bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    open_skel.rodata_mut().pid_counter = pid_count as i32;
    //open_skel.rodata().pid_counter = pid_count as i32;

    let mut skel = open_skel.load()?;

    for (index,pid) in pids.iter().enumerate(){
        let pid_vec = u32_to_u8_array_little_endian(*pid);
        skel.maps_mut().pids().update(&pid_vec, &pid_vec, MapFlags::ANY)?;
    } 
    
    let _tracepoint_sys_enter = skel.progs_mut().trace_sys_enter().attach_tracepoint("raw_syscalls", "sys_enter")?;

    let _tracepoint_sys_exit = skel.progs_mut().trace_sys_exit().attach_tracepoint("raw_syscalls", "sys_exit")?;
    

    let mut uprobes:Vec<Link> = vec![];

    //If we are tracing containers we need to find the correct file
    if containers.len() > 0{
        for (index, pid) in pids.clone().iter().enumerate() {

            let container_location = auxiliary::get_overlay2_location(&containers[index]).unwrap();
    
            let binary_location = format!("{}{}", container_location, binary_path);
    
    
            for (index_function, function) in functions.clone().iter().enumerate(){
                let opts = UprobeOpts{ref_ctr_offset:0,cookie:index_function as u64,retprobe:false,func_name:function.clone(),..Default::default()};
    
                let uprobe = skel.progs_mut().handle_uprobe().attach_uprobe_with_opts(*pid as i32, binary_location.clone(), 0, opts).expect("failed to attach prog");
        
                uprobes.push(uprobe);

                println!("Inserted uprobe for function {} in container {} with cookie {}",function.clone(),containers[index].clone(),index);
        
            }
        }
    }else{
        for (index, pid) in pids.clone().iter().enumerate() {    
    
            for function in functions.clone(){
                let opts = UprobeOpts{ref_ctr_offset:0,cookie:0,retprobe:false,func_name:function.clone(),..Default::default()};
    
                let uprobe = skel.progs_mut().handle_uprobe().attach_uprobe_with_opts(*pid as i32, binary_path.clone(), 0, opts).expect("failed to attach prog");
        
                uprobes.push(uprobe);
        
            }
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

    collect_uprobe_stats(skel.maps().uprobe_counters(),functions.clone());
    Ok(())
}