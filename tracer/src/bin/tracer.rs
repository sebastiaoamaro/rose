use libc::{rlimit, setrlimit, RLIMIT_NOFILE};
use std::env;
use tracer::manager;
use tracer::production_tracer;
use tracer::rw_tracer;
use tracer::statistics_tracer;
use tracer::sys_all_tracer;

fn main() {
    let new_limit = rlimit {
        rlim_cur: 65356, // Soft limit
        rlim_max: 65356, // Hard limit
    };

    unsafe {
        if setrlimit(RLIMIT_NOFILE, &new_limit) != 0 {
            eprintln!("Error setting RLIMIT_NOFILE");
        } else {
            //println!("Successfully set the max open file limit to {}", limit);
        }
    }

    let args: Vec<String> = env::args().collect();

    let type_and_mode: Vec<&str> = args[1].split(',').collect();

    let tracing_type = type_and_mode[0].trim();

    let mode = type_and_mode[1].trim();

    if tracing_type == "sys_all_trace" {
        println!("Started SYS_ALL_TRACER");
        let functions_file = &args[2];

        let mut functions = vec![];
        if functions_file.len() > 0 {
            functions = manager::parse_file_to_pairs(&functions_file).clone();
        }

        let binary_path = args[3].to_string();
        let node_and_pid = args[4].to_string();
        let mut network_interface = "".to_string();
        if args.len() > 5 {
            network_interface = args[5].to_string();
        }

        sys_all_tracer::run_tracing(
            mode.to_string(),
            functions,
            binary_path,
            node_and_pid,
            network_interface,
        )
        .expect("Something went wrong with tracer");
    }
    if tracing_type == "rw_trace" {
        println!("Started RW_TRACER");

        let functions_file = &args[2];

        let mut functions = vec![];
        if functions_file.len() > 0 {
            functions = manager::parse_file_to_pairs(&functions_file).clone();
        }

        let binary_path = args[3].to_string();
        let node_and_pid = args[4].to_string();
        let mut network_interface = "".to_string();
        if args.len() > 5 {
            network_interface = args[5].to_string();
        }

        rw_tracer::run_tracing(
            mode.to_string(),
            functions,
            binary_path,
            node_and_pid,
            network_interface,
        )
        .expect("Something went wrong with tracer");
    }

    if tracing_type == "stats_trace" {
        println!("Started STATS_TRACER");

        let functions_file = &args[2];

        let mut functions = vec![];
        if functions_file.len() > 0 {
            functions = manager::parse_file_to_pairs(&functions_file).clone();
        }

        let binary_path = args[3].to_string();
        let node_and_pid = args[4].to_string();
        let mut network_interface = "".to_string();
        if args.len() > 5 {
            network_interface = args[5].to_string();
        }

        statistics_tracer::run_tracing(
            mode.to_string(),
            functions,
            binary_path,
            node_and_pid,
            network_interface,
        )
        .expect("Something went wrong with tracer");
    }

    //This is the tracer that runs in production, it has mode container and process
    if tracing_type == "production_trace" {
        println!("Started PROD_TRACER");

        let functions_file = &args[2];

        let mut functions = vec![];
        if functions_file.len() > 0 {
            functions = manager::parse_file_to_pairs(&functions_file).clone();
        }

        let binary_path = args[3].to_string();
        let node_and_pid = args[4].to_string();
        let mut network_interface = "".to_string();
        if args.len() > 5 {
            network_interface = args[5].to_string();
        }

        production_tracer::run_tracing(
            mode.to_string(),
            functions,
            binary_path,
            node_and_pid,
            network_interface,
        )
        .expect("Something went wrong with tracer");
    }
    println!("Finished tracing mode: {}", tracing_type);

    return;
}
