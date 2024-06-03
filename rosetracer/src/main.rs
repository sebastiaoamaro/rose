use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::libbpf_sys::BPF_ANY;
use libbpf_rs::MapFlags;
use core::time::Duration;
use std::thread::sleep;
use libbpf_rs::PerfBufferBuilder;
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::fs::File;
use std::io::{self, BufRead};
use std::env;

mod trace {
    include!(concat!(env!("OUT_DIR"), "/trace.skel.rs"));
}
use trace::*;

type Event = trace_bss_types::event;
unsafe impl Plain for Event {}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let filename = &args[1];

    let pids = read_numbers_from_file(filename).unwrap().clone();

    let pid_count = pids.len().clone();

    //Build the BPF program
    let mut skel_builder = TraceSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    open_skel.rodata().pid_counter = pid_count as i32;

    let mut skel = open_skel.load()?;

    let _tracepoint_write_enter = skel.progs_mut().trace_write().attach_tracepoint("syscalls", "sys_enter_write")?;

    let _tracepoint_enter_read = skel.progs_mut().trace_read_enter().attach_tracepoint("syscalls", "sys_enter_read")?;

    let _tracepoint_exit_read = skel.progs_mut().trace_read_exit().attach_tracepoint("syscalls", "sys_exit_read")?;

    let _tracepoint_sys_enter = skel.progs_mut().trace_sys_enter().attach_tracepoint("raw_syscalls", "sys_enter")?;

    let _tracepoint_sys_exit = skel.progs_mut().trace_sys_exit().attach_tracepoint("raw_syscalls", "sys_exit")?;


    for (index,pid) in pids.iter().enumerate(){
        let pid_vec = u32_to_u8_array_little_endian(*pid);
        skel.maps_mut().pids().update(&pid_vec, &pid_vec, MapFlags::ANY)?;
    }


    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_secs(2));
    }

    Ok(())
}

fn read_numbers_from_file(filename: &str) -> io::Result<Vec<u32>> {
    let path = Path::new(filename);
    let file = File::open(&path)?;
    let reader = io::BufReader::new(file);

    let mut numbers = Vec::new();

    for line in reader.lines() {
        let line = line?;
        match line.trim().parse::<u32>() {
            Ok(num) => numbers.push(num),
            Err(e) => eprintln!("Error parsing number '{}': {}", line, e),
        }
    }

    Ok(numbers)
}


fn u32_to_u8_array_little_endian(value: u32) -> [u8; 4] {
    [
        value as u8,
        (value >> 8) as u8,
        (value >> 16) as u8,
        (value >> 24) as u8,
    ]
}