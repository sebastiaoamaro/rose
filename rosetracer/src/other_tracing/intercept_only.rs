use anyhow::Result;
use core::time::Duration;
use std::mem::MaybeUninit;
use libbpf_rs::{MapCore, MapFlags};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;

use crate::auxiliary;

mod intercept_only {
    include!(concat!(env!("OUT_DIR"), "/intercept_only.skel.rs"));
}
use intercept_only::*;

pub fn run_tracing(
    pids: Vec<i32>,
    pid_count: usize,
    _containers: Vec<String>,
    _functions: Vec<String>,
) -> Result<()> {
    auxiliary::bump_memlock_rlimit()?;
    //Build the BPF program
    let skel_builder = InterceptOnlySkelBuilder::default();

    //skel_builder.obj_builder.debug(true);
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.pid_counter = pid_count as i32;
    //open_skel.rodata().pid_counter = pid_count as i32;

    let skel = open_skel.load()?;

    let _tracepoint_sys_enter = skel
        .progs
        .trace_sys_enter
        .attach_tracepoint("raw_syscalls", "sys_enter")?;

    let _tracepoint_sys_exit = skel
        .progs
        .trace_sys_exit
        .attach_tracepoint("raw_syscalls", "sys_exit")?;

    for (_index, pid) in pids.iter().enumerate() {
        let pid_vec = auxiliary::u32_to_u8_array_little_endian(*pid);
        skel.maps
            .pids
            .update(&pid_vec, &pid_vec, MapFlags::ANY)?;
    }

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

