use anyhow::{anyhow, bail, Context, Result};
use core::time::Duration;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::UprobeOpts;
use std::env;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::sleep;

mod uprobes {
    include!(concat!(env!("OUT_DIR"), "/uprobes.skel.rs"));
}
use uprobes::*;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Please provide a pid as an argument.");
        return Ok(());
    }

    let arg1 = &args[1];
    let pid: i32 = arg1.parse().expect("Please provide a valid integer");

    //Build the BPF program
    let mut skel_builder = UprobesSkelBuilder::default();

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    let mut skel = open_skel.load()?;

    let binary_path = "/home/sebastiaoamaro/phd/torefidevel/tests/uprobetest/src/write"
        .to_string()
        .clone();

    let function_name = "my_test_function".to_string().clone();

    println!(
        "function name is {} binary_location is {} and symbol location is {} and pid is {}",
        function_name,
        binary_path.clone(),
        0,
        pid as i32
    );

    let opts = UprobeOpts {
        ..Default::default()
    };

    let uprobe = skel.progs_mut().handle_uprobe().attach_uprobe_with_opts(
        pid as i32,
        binary_path.clone(),
        0,
        opts,
    );

    match &uprobe {
        Ok(..) => {
            println!("Inserted probe with name {}", function_name);
        }
        Err(e) => {
            println!("Failed to insert uprobe error: {}", e);
        }
    }

    uprobe.unwrap().detach().expect("Failed");

    println!("Sucessfully detached \n");

    let opts_ret = UprobeOpts {
        func_name: function_name.clone(),
        retprobe: true,
        ..Default::default()
    };

    let uprobe_ret = skel
        .progs_mut()
        .handle_uprobe_ret()
        .attach_uprobe_with_opts(pid as i32, binary_path.clone(), 0, opts_ret);
    match &uprobe_ret {
        Ok(..) => {
            println!("Inserted uprobe_ret with name {}", function_name);
        }
        Err(e) => {
            println!("Failed to insert uprobe error: {}", e);
        }
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

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}
