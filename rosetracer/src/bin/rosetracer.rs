use anyhow::{Ok, Result};
use libc::{rlimit, setrlimit, RLIMIT_NOFILE};
use std::{env, process::exit};

use rosetracer::auxiliary;
use rosetracer::tracer;
use rosetracer::statisticstracer;
use rosetracer::production_tracer;

fn main() -> Result<()> {

    let new_limit = rlimit {
        rlim_cur: 65356,   // Soft limit
        rlim_max: 65356,   // Hard limit
    };

    unsafe {
        if setrlimit(RLIMIT_NOFILE, &new_limit) != 0 {
            eprintln!("Error setting RLIMIT_NOFILE");
        } else {
            //println!("Successfully set the max open file limit to {}", limit);
        }
    }
    
    let args: Vec<String> = env::args().collect();

    let type_and_mode:Vec<&str> = args[1].split(',').collect();

    let tracing_type = type_and_mode[0].trim();

    let mode = type_and_mode[1].trim();


    if tracing_type == "full_trace"{
        println!("Started full_tracer");

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
        
        //exit(1);
    }
    if tracing_type == "stats_trace"{
        println!("Started stats_tracer");

        let functions_file = &args[2];

        let functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();

        let binary_path = args[3].to_string();

        let node_and_pid = args[4].to_string();

        statisticstracer::run_tracing(mode.to_string(),functions,binary_path,node_and_pid).expect("Something went wrong with tracer");
        
        //exit(1);
    }

    //This is the tracer that runs in production, it has mode container and process
    if tracing_type == "production_trace"{
        println!("Started production_tracer");
    
        let functions_file = &args[2];

        let mut functions = vec![];
        if functions_file.len() > 0{
            functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();
        }

        let binary_path = args[3].to_string();

        let node_and_pid = args[4].to_string();

        let mut network_interface = "".to_string();
        if args.len() > 5{
            network_interface = args[5].to_string();
        }

        production_tracer::run_tracing(mode.to_string(),functions,binary_path,node_and_pid,network_interface).expect("Something went wrong with tracer");
        //exit(1);
    }
    println!("Finished tracing mode: {}",tracing_type);

    exit(1);
}
