use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::Link;
use std::env;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Ok, Result};
use xdp::XdpSkelBuilder;

mod xdp {
    include!(concat!(env!("OUT_DIR"), "/xdp.skel.rs"));
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let if_index = args[1].parse::<i32>().unwrap();

    let container_type = args[2].parse::<i32>().unwrap();

    let skel_builder = XdpSkelBuilder::default();

    let mut open_object_tracer = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object_tracer)?;
    let skel = open_skel.load()?;
    //println!("If index is {}", if_index - 1);
    let xdp_prog: Option<Link> = match container_type {
        0 => Some(
            skel.progs
                .xdp_pass
                .attach_xdp(if_index)
                .expect("Failed to attach XDP program"),
        ),
        1 => Some(
            skel.progs
                .xdp_pass
                .attach_xdp(2)
                .expect("Failed to attach XDP program"),
        ),
        2 => Some(
            skel.progs
                .xdp_pass
                .attach_xdp(if_index - 1)
                .expect("Failed to attach XDP program"),
        ),
        3 => Some(
            skel.progs
                .xdp_pass
                .attach_xdp(2)
                .expect("Failed to attach XDP program"),
        ),
        _ => None,
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_secs(1));
    }
    if !xdp_prog.is_none() {
        xdp_prog.unwrap().detach()?;
    }

    Ok(())
}
