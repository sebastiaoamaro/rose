use crate::auxiliary::{self, pin_maps, start_tracing};
use crate::skel_types::{statistics_tracer, SkelEnum};
use anyhow::Result;
use auxiliary::pin_maps::PinMapsSkelBuilder;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::{Link, OpenObject};
use std::collections::HashMap;
use std::mem::MaybeUninit;

pub fn run_tracing(
    mode: String,
    functions: Vec<(String, usize)>,
    binary_path: String,
    nodes_info: String,
    network_device: String,
) -> Result<()> {
    println!(
        "Starting STATS_TRACER, collecting counter for {} functions",
        functions.len(),
    );
    auxiliary::bump_memlock_rlimit()?;
    //Init maps
    let skel_builder_maps = PinMapsSkelBuilder::default();
    let mut open_object_maps = MaybeUninit::uninit();
    let open_skel_maps = skel_builder_maps.open(&mut open_object_maps)?;
    let mut skel_maps = open_skel_maps.load()?;
    pin_maps(&mut skel_maps);

    //Init variables for tracing
    let mut hashmap_links: HashMap<i32, Vec<Link>> = HashMap::new();
    let mut hashmap_pid_to_node: HashMap<i32, String> = HashMap::new();
    let mut hashmap_node_to_pid: HashMap<String, i32> = HashMap::new();

    //Build the BPF program
    let skel_builder = statistics_tracer::StatisticsTracerSkelBuilder::default();
    let open_object = Box::new(MaybeUninit::<OpenObject>::uninit());
    // Leak the Box to get a reference with a 'static lifetime.
    let open_object_ref: &'static mut MaybeUninit<OpenObject> = Box::leak(open_object);

    let open_skel = skel_builder.open(open_object_ref)?;
    let mut skel: statistics_tracer::StatisticsTracerSkel<'static> = open_skel.load()?;

    let mut tracepoint_vector = vec![];

    let tracepoint_sys_enter = skel
        .progs
        .trace_sys_enter
        .attach_tracepoint(libbpf_rs::TracepointCategory::RawSyscalls, "sys_enter")
        .expect("Failed to attach sys_exit");

    let tracepoint_sys_exit = skel
        .progs
        .trace_sys_exit
        .attach_tracepoint(libbpf_rs::TracepointCategory::RawSyscalls, "sys_exit")
        .expect("Failed to attach sys_exit");

    let tracepoint_proc_start = skel
        .progs
        .handle_exec
        .attach_tracepoint(libbpf_rs::TracepointCategory::Sched, "sched_process_exec")
        .expect("Failed to attach sched_process_exec");

    tracepoint_vector.push(tracepoint_sys_enter);
    tracepoint_vector.push(tracepoint_sys_exit);
    tracepoint_vector.push(tracepoint_proc_start);

    let mut skel_enum: SkelEnum<'_, 'static> = SkelEnum::StatisticsTracer(&mut skel);
    start_tracing(
        mode,
        functions,
        binary_path,
        nodes_info,
        network_device,
        &mut skel_enum,
        &mut skel_maps,
        &mut hashmap_pid_to_node,
        &mut hashmap_node_to_pid,
        &mut hashmap_links,
    )
    .expect("Failed to start_tracing in prod_tracer");

    Ok(())
}
