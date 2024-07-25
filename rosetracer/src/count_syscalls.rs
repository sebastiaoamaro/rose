use anyhow::Result;
use core::time::Duration;
use libbpf_rs::MapFlags;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;

use crate::auxiliary;

mod count_syscalls {
    include!(concat!(env!("OUT_DIR"), "/count_syscalls.skel.rs"));
}
use count_syscalls::*;

pub fn run_tracing(
    pids: Vec<u32>,
    pid_count: usize,
    containers: Vec<String>,
    functions: Vec<String>,
) -> Result<()> {
    //Build the BPF program
    let mut skel_builder = CountSyscallsSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    auxiliary::bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    open_skel.rodata().pid_counter = pid_count as i32;

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
