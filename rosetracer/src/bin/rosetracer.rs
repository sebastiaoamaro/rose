use anyhow::{Ok, Result};
use libc::{rlimit, setrlimit, RLIMIT_NOFILE};
use std::{env, process::exit};

use rosetracer::auxiliary;
use rosetracer::tracer;
use rosetracer::statisticstracer;
use rosetracer::productiontracer;
use rosetracer::other_tracing;

fn main() -> Result<()> {

    let limit = 65356;
    let new_limit = rlimit {
        rlim_cur: 65356,   // Soft limit
        rlim_max: 65356,   // Hard limit
    };

    unsafe {
        if setrlimit(RLIMIT_NOFILE, &new_limit) != 0 {
            eprintln!("Error setting RLIMIT_NOFILE");
        } else {
            println!("Successfully set the max open file limit to {}", limit);
        }
    }
    
    let args: Vec<String> = env::args().collect();

    let tracing_type = &args[1];

    if tracing_type.as_str() == "tracer"{
        println!("Started tracer with args {}",args.len());

        for arg in args.clone(){
            println!(" Arg is {}|",arg);
        }
        let functions_file = &args[2];

        let collect_process_info_pipe = args[4].to_string();
        
        //If we want to trace function symbols
        if args[2].len() > 0{
            let functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();

            let binary_path = args[3].to_string();
            tracer::run_tracing(functions,binary_path,collect_process_info_pipe).expect("Something went wrong with tracer");

        //If we do not not want to trace symbols, we can just pass an empty vector and empty binary path
        }else{
            let functions = vec![];
            let binary_path = "".to_string();
            tracer::run_tracing(functions,binary_path,collect_process_info_pipe).expect("Something went wrong with tracer");
        }
        
        exit(1);
    }
    if tracing_type.as_str() == "stats_tracer"{
        println!("Started stats_tracer");
        let functions_file = &args[2];

        let functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();

        let binary_path = args[3].to_string();

        let node_and_pid = args[4].to_string();

        statisticstracer::run_tracing(functions,binary_path,node_and_pid).expect("Something went wrong with tracer");
        
        exit(1);
    }
    if tracing_type.as_str() == "production_tracer"{
        println!("Started production_tracer");
        let functions_file = &args[2];

        let functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();

        let binary_path = args[3].to_string();

        let node_and_pid = args[4].to_string();

        productiontracer::run_tracing(functions,binary_path,node_and_pid).expect("Something went wrong with tracer");
        
        exit(1);
    }

    //Below are old tests for overhead of tracing things using eBPF

    let pids_file = &args[2];

    let mut containers = vec![];
    let mut functions = vec![];


    let pids = auxiliary::read_numbers_from_file(pids_file)
        .unwrap()
        .clone();

    println!("Started tracing for \nPids:{:?}", pids);

    let pid_count = pids.len().clone();

    //skel_builder.obj_builder.debug(true);

    match tracing_type.as_str() {
        "intercept" => {
            other_tracing::intercept_only::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with intercept \n");
        }
        "intercept_and_count" => {
            other_tracing::intercept_and_count::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with intercept_and_count \n");
        }
        "count_syscalls" => {
            other_tracing::count_syscalls::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with count_syscalls \n");
        }
        "save_info" => {
            other_tracing::save_info::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with save_info \n");
        }
        "save_io" => {
            other_tracing::save_io::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with save_io \n");
        },
        "uprobes" => {

            let functions_file = &args[3];

            functions = auxiliary::read_names_from_file(&functions_file)
                .unwrap()
                .clone();
    
    
            if args.len() == 5{
                let filename_for_container_names = &args[4];
    
                containers = auxiliary::read_names_from_file(filename_for_container_names)
                .unwrap()
                .clone();
            }

            //Needs binary_path
            other_tracing::uprobes::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with save_io \n");
        }
        _ => {
            println!("Does not match any tracing type");
        }
    }
    Ok(())
}
