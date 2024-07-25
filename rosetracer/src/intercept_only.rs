use anyhow::{anyhow, bail, Context, Result};
use core::time::Duration;
use libbpf_rs::libbpf_sys::BPF_ANY;
use libbpf_rs::MapFlags;
use libbpf_rs::PerfBufferBuilder;
use libloading::{Library, Symbol};
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use rand::Rng;
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;

use crate::auxiliary;

mod intercept_only {
    include!(concat!(env!("OUT_DIR"), "/intercept_only.skel.rs"));
}
use intercept_only::*;

pub fn run_tracing(
    pids: Vec<u32>,
    pid_count: usize,
    containers: Vec<String>,
    functions: Vec<String>,
) -> Result<()> {
    //Build the BPF program
    let mut skel_builder = InterceptOnlySkelBuilder::default();

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

fn uprobes() {
    /*    let library;
        unsafe {
            library =
                Library::new("/home/sebastiaoamaro/phd/torefidevel/rosetracer/src/uprobe_helper.so")
                    .unwrap();
        }
        type ConcatStrings = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> u64;

        let binary_path = "/usr/local/bin/redis-server".to_string();

        for (index, pid) in pids.clone().iter().enumerate() {
            for function in functions.clone() {
                let mut rng = rand::thread_rng();
                let chance: f64 = rng.gen();

                if chance > 0.15 {
                    continue;
                }

                let container_location = auxiliary::get_overlay2_location(&containers[index]).unwrap();

                let binary_location = format!("{}{}", container_location, binary_path);

                //let symbol_location = find_symbol_in_binary(&binary_location,"je_opt_tcache_max").unwrap();
                let symbol_location: u64;
                unsafe {
                    let elf_func_offset_finder: Symbol<ConcatStrings> = library
                        .get(b"get_elf_func_offset")
                        .expect("Failed to load get_elf_func_offset function");

                    let path = CString::new(binary_location.clone()).expect("CString::new failed");
                    let func_name = CString::new(function.clone()).expect("CString::new failed");

                    symbol_location = elf_func_offset_finder(path.as_ptr(), func_name.as_ptr());

                    //println!("symbol_location is {}",symbol_location);
                }

                //println!("function name is {} binary_location is {} and symbol location is {} and pid is {}",function.clone(),binary_location,symbol_location,*pid as i32);

                let uprobe = skel.progs_mut().dummy_kprobe().attach_uprobe(
                    false,
                    *pid as i32,
                    binary_location,
                    symbol_location as usize,
                );

                match uprobe {
                    Ok(uprobe) => {
                        println!("Inserted probe with name {}", function);
                    }
                    Err(e) => {
                        println!("Failed to insert uprobe error: {}", e);
                    }
                }
                skel.maps_mut().uprobe_map().update(
                    &auxiliary::u64_to_u8_array_little_endian(symbol_location),
                    &auxiliary::u32_to_u8_array_little_endian(0),
                    MapFlags::ANY,
                )?;

                auxiliary::write_to_file(
                    "functions_probed.txt".to_string(),
                    format!("name:{} location:{}\n", function.clone(), symbol_location),
                );
            }
        }

        auxiliary::write_to_file("check.txt".to_string(), "true".to_string());

    */
}
