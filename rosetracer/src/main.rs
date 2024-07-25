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

mod auxiliary;
mod count_syscalls;
mod intercept_and_count;
mod intercept_only;
mod save_info;
mod save_io;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let pids_file = &args[1];

    let tracing_type = &args[2];

    let mut containers = vec![];
    let mut functions = vec![];

    if tracing_type == "uprobes" {
        let filename_for_container_names = &args[3];

        let functions_file = &args[4];

        containers = auxiliary::read_names_from_file(filename_for_container_names)
            .unwrap()
            .clone();

        functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();
    }

    let pids = auxiliary::read_numbers_from_file(pids_file)
        .unwrap()
        .clone();

    println!("Started tracing for \nPids:{:?}", pids);

    let pid_count = pids.len().clone();

    //skel_builder.obj_builder.debug(true);

    match tracing_type.as_str() {
        "intercept" => {
            intercept_only::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with intercept \n");
        }
        "intercept_and_count" => {
            intercept_and_count::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with intercept_and_count \n");
        }
        "count_syscalls" => {
            count_syscalls::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with count_syscalls \n");
        }
        "save_info" => {
            save_info::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with save_info \n");
        }
        "save_io" => {
            save_io::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with save_io \n");
        }
        _ => {
            println!("Not found command");
        }
    }
    Ok(())
}
