use crate::auxiliary::pin_maps::PinMapsSkel;
use crate::auxiliary::{
    end_trace, process_syscall_counters_map, process_uprobes_counters_map, write_to_file,
};
use libbpf_rs::Link;
use libbpf_rs::UprobeOpts;
use libbpf_rs::{MapCore, MapFlags};
use std::collections::HashMap;

pub mod production_tracer {
    include!(concat!(env!("OUT_DIR"), "/production_tracer.skel.rs"));
}

pub mod rw_tracer {
    include!(concat!(env!("OUT_DIR"), "/rw_tracer.skel.rs"));
}

pub mod sys_all_tracer {
    include!(concat!(env!("OUT_DIR"), "/sys_all_tracer.skel.rs"));
}

pub mod statistics_tracer {
    include!(concat!(env!("OUT_DIR"), "/statistics_tracer.skel.rs"));
}

use production_tracer::*;
use rw_tracer::*;
use statistics_tracer::*;
use sys_all_tracer::*;

pub trait SkelUpdatePidTrait {
    fn update(&mut self, pid_vec: &[u8; 4], one: &[u8; 4]);
}
pub trait SkelAttachUprobe {
    fn attach_uprobe(
        &mut self,
        index_function: usize,
        function: &String,
        function_offset: usize,
        binary_path: String,
        pid: i32,
        hashmap_links: &mut HashMap<i32, Vec<Link>>,
    );
}

pub trait SkelEndTraceTrait {
    fn end_trace(
        &mut self,
        skel_maps: &mut PinMapsSkel,
        hashmap_pid_to_node: &mut HashMap<i32, String>,
        functions: Vec<(String, usize)>,
    );
}

pub enum SkelEnum<'a, 'obj> {
    Production(&'a mut ProductionTracerSkel<'obj>),
    SysAllTracer(&'a mut SysAllTracerSkel<'obj>),
    RwTracer(&'a mut RwTracerSkel<'obj>),
    StatisticsTracer(&'a mut StatisticsTracerSkel<'obj>),
}

impl<'a, 'obj> SkelUpdatePidTrait for SkelEnum<'a, 'obj> {
    fn update(&mut self, pid_vec: &[u8; 4], one: &[u8; 4]) {
        match self {
            SkelEnum::Production(skel_instance) => {
                skel_instance
                    .maps
                    .pid_tree
                    .update(pid_vec, one, MapFlags::ANY)
                    .expect("Failed to add pid to eBPF");
            }
            SkelEnum::SysAllTracer(skel_instance) => {
                skel_instance
                    .maps
                    .pid_tree
                    .update(pid_vec, one, MapFlags::ANY)
                    .expect("Failed to add pid to eBPF");
            }
            SkelEnum::RwTracer(skel_instance) => {
                skel_instance
                    .maps
                    .pid_tree
                    .update(pid_vec, one, MapFlags::ANY)
                    .expect("Failed to add pid to eBPF");
            }
            SkelEnum::StatisticsTracer(skel_instance) => {
                skel_instance
                    .maps
                    .pid_tree
                    .update(pid_vec, one, MapFlags::ANY)
                    .expect("Failed to add pid to eBPF");
            }
        }
    }
}
impl<'a, 'obj> SkelAttachUprobe for SkelEnum<'a, 'obj> {
    fn attach_uprobe(
        &mut self,
        index_function: usize,
        function: &String,
        function_offset: usize,
        binary_path: String,
        pid: i32,
        hashmap_links: &mut HashMap<i32, Vec<Link>>,
    ) {
        match self {
            SkelEnum::Production(skel_instance) => {
                //libbpf-rs is broken and miscalculates offsets
                let opts = UprobeOpts {
                    cookie: index_function as u64,
                    retprobe: false,
                    ..Default::default()
                };
                let uprobe = skel_instance.progs.handle_uprobe.attach_uprobe_with_opts(
                    pid,
                    binary_path.clone(),
                    function_offset,
                    opts,
                );

                match uprobe {
                    Ok(uprobe_injected) => {
                        hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                        //println!("Injected in pos {} in pid {}", index_function, pid);
                    }
                    Err(e) => {
                        println!("Failed:{}, err:{}", function.clone(), e);
                    }
                }
            }
            SkelEnum::SysAllTracer(skel_instance) => {
                //libbpf-rs is broken and miscalculates offsets
                let opts = UprobeOpts {
                    cookie: index_function as u64,
                    retprobe: false,
                    ..Default::default()
                };
                let uprobe = skel_instance.progs.handle_uprobe.attach_uprobe_with_opts(
                    -1,
                    binary_path.clone(),
                    function_offset,
                    opts,
                );

                match uprobe {
                    Ok(uprobe_injected) => {
                        hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                        //println!("Injected in pos {} in pid {}", index_function, pid);
                    }
                    Err(e) => {
                        println!("Failed:{}, err:{}", function.clone(), e);
                    }
                }
            }
            SkelEnum::RwTracer(skel_instance) => {
                //libbpf-rs is broken and miscalculates offsets
                let opts = UprobeOpts {
                    cookie: index_function as u64,
                    retprobe: false,
                    ..Default::default()
                };
                let uprobe = skel_instance.progs.handle_uprobe.attach_uprobe_with_opts(
                    pid,
                    binary_path.clone(),
                    function_offset,
                    opts,
                );
                match uprobe {
                    Ok(uprobe_injected) => {
                        hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                        //println!("Injected in pos {} in pid {}", index_function, pid);
                    }
                    Err(e) => {
                        println!("Failed:{}, err:{}", function.clone(), e);
                    }
                }
            }
            SkelEnum::StatisticsTracer(skel_instance) => {
                //libbpf-rs is broken and miscalculates offsets
                let opts = UprobeOpts {
                    cookie: index_function as u64,
                    retprobe: false,
                    ..Default::default()
                };
                let uprobe = skel_instance.progs.handle_uprobe.attach_uprobe_with_opts(
                    pid,
                    binary_path.clone(),
                    function_offset,
                    opts,
                );
                match uprobe {
                    Ok(uprobe_injected) => {
                        hashmap_links.get_mut(&pid).unwrap().push(uprobe_injected);
                        //println!("Injected in pos {} in pid {}", index_function, pid);
                    }
                    Err(e) => {
                        println!(
                            "Failed to inject uprobe in pos: {} offet: {}: pid:{}, error:{}",
                            index_function, function_offset, pid, e
                        );
                        write_to_file(
                            "/tmp/failed_probes.txt".to_string(),
                            format!("{},{}\n", function.clone(), index_function,),
                        )
                        .expect("Failed to write to failed_probes.txt");
                    }
                }
            }
        }
    }
}
impl<'a, 'obj> SkelEndTraceTrait for SkelEnum<'a, 'obj> {
    fn end_trace(
        &mut self,
        skel_maps: &mut PinMapsSkel,
        hashmap_pid_to_node: &mut HashMap<i32, String>,
        functions: Vec<(String, usize)>,
    ) {
        match self {
            SkelEnum::Production(skel_instance) => {
                end_trace(
                    &mut skel_instance.maps.pid_tree,
                    &mut skel_instance.maps.fd_to_name,
                    &mut skel_instance.maps.dup_map,
                    &mut skel_maps.maps.network_information,
                    &mut skel_maps.maps.history_delays,
                    &mut skel_instance.maps.history,
                    hashmap_pid_to_node,
                    &functions,
                );
            }
            SkelEnum::SysAllTracer(skel_instance) => {
                end_trace(
                    &mut skel_instance.maps.pid_tree,
                    &mut skel_instance.maps.fd_to_name,
                    &mut skel_instance.maps.dup_map,
                    &mut skel_maps.maps.network_information,
                    &mut skel_maps.maps.history_delays,
                    &mut skel_instance.maps.history,
                    hashmap_pid_to_node,
                    &functions,
                );
            }
            SkelEnum::RwTracer(skel_instance) => {
                end_trace(
                    &mut skel_instance.maps.pid_tree,
                    &mut skel_instance.maps.fd_to_name,
                    &mut skel_instance.maps.dup_map,
                    &mut skel_maps.maps.network_information,
                    &mut skel_maps.maps.history_delays,
                    &mut skel_instance.maps.history,
                    hashmap_pid_to_node,
                    &functions,
                );
            }
            SkelEnum::StatisticsTracer(skel_instance) => {
                end_trace(
                    &mut skel_instance.maps.pid_tree,
                    &mut skel_instance.maps.fd_to_name,
                    &mut skel_instance.maps.dup_map,
                    &mut skel_maps.maps.network_information,
                    &mut skel_maps.maps.history_delays,
                    &mut skel_instance.maps.history,
                    hashmap_pid_to_node,
                    &functions,
                );
                process_uprobes_counters_map(&mut skel_instance.maps.uprobes_counters, &functions);
                process_syscall_counters_map(&mut skel_instance.maps.syscall_counters, &functions);
            }
        }
    }
}
