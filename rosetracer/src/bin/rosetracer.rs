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

        let mode = args[2].to_string();

        let functions_file = &args[3];

        let functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();

        let binary_path = args[4].to_string();

        let node_and_pid = args[5].to_string();

        statisticstracer::run_tracing(mode,functions,binary_path,node_and_pid).expect("Something went wrong with tracer");
        
        exit(1);
    }

    //This is the tracer that runs in production, it has mode container and process
    if tracing_type.as_str() == "production_tracer"{
        println!("Started production_tracer");
        
        let mode = args[2].to_string();

        let functions_file = &args[3];

        let functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();

        let binary_path = args[4].to_string();

        let node_and_pid = args[5].to_string();

        let network_interface = args[6].to_string();

        productiontracer::run_tracing(mode,functions,binary_path,node_and_pid,network_interface).expect("Something went wrong with tracer");
        
        exit(1);
    }

    Ok(())
}
