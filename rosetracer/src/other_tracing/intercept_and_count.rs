use anyhow::Result;
use core::time::Duration;
use libbpf_rs::MapFlags;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;

use crate::auxiliary;

mod intercept_and_count {
    include!(concat!(env!("OUT_DIR"), "/intercept_and_count.skel.rs"));
}
use intercept_and_count::*;

pub fn run_tracing(
    pids: Vec<i32>,
    pid_count: usize,
    containers: Vec<String>,
    functions: Vec<String>,
) -> Result<()> {
    //Build the BPF program
    let mut skel_builder = InterceptAndCountSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    auxiliary::bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    open_skel.rodata_mut().pid_counter = pid_count as i32;
    //open_skel.rodata().pid_counter = pid_count as i32;

    let mut skel = open_skel.load()?;

    let _tracepoint_sys_enter = skel
        .progs_mut()
        .trace_sys_enter()
        .attach_tracepoint("raw_syscalls", "sys_enter")?;

    let _tracepoint_sys_exit = skel
        .progs_mut()
        .trace_sys_exit()
        .attach_tracepoint("raw_syscalls", "sys_exit")?;

    for (index, pid) in pids.iter().enumerate() {
        let pid_vec = auxiliary::u32_to_u8_array_little_endian(*pid);
        skel.maps_mut()
            .pids()
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
