use anyhow::Result;
use libbpf_rs::Link;
use libbpf_rs::UprobeOpts;
use crate::auxiliary;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use core::time::Duration;
use std::thread::sleep;

mod uprobes {
    include!(concat!(env!("OUT_DIR"), "/uprobes.skel.rs"));
}
use uprobes::*;

pub fn run_tracing(
    pids: Vec<i32>,
    pid_count: usize,
    _containers: Vec<String>,
    _functions: Vec<String>,
) -> Result<()>{ 

    //Build the BPF program
    let skel_builder = UprobesSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    auxiliary::bump_memlock_rlimit()?;
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.pid_counter = pid_count as i32;
    //open_skel.rodata().pid_counter = pid_count as i32;

    let skel = open_skel.load()?;

    //let binary_path = "/home/sebastiaoamaro/phd/torefidevel/tests/traceroverhead/write".to_string().clone();

    let binary_path = "/vagrant/tests/traceroverhead/write".to_string().clone();
    let function_name = "my_test_function".to_string();

    let mut uprobes:Vec<Link> = vec![];

    for (_index, pid) in pids.clone().iter().enumerate() {
        let opts = UprobeOpts{ref_ctr_offset:0,cookie:0,retprobe:false,func_name:function_name.clone(),..Default::default()};

        let uprobe = skel.progs.handle_uprobe.attach_uprobe_with_opts(*pid as i32, binary_path.clone(), 0, opts).expect("failed to attach prog");

        uprobes.push(uprobe);

    
    }


    //let container_location = auxiliary::get_overlay2_location(&containers[index]).unwrap();

    //let binary_location = format!("{}{}", container_location, binary_path);



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