use anyhow::Result;
use std::env;

mod auxiliary;
mod tracer;
mod other_tracing;


fn main() -> Result<()> {
    
    println!("Started TRACER");

    let args: Vec<String> = env::args().collect();

    let tracing_type = &args[0];

    if tracing_type.as_str() == "tracer"{

        let functions_file = &args[1];

        let functions = auxiliary::read_names_from_file(&functions_file)
            .unwrap()
            .clone();

        let binary_path = args[2].to_string();

        let collect_process_info_pipe = args[3].to_string();

        tracer::run_tracing(functions,binary_path,collect_process_info_pipe)
            .expect("Something went wrong with tracer");

    }

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
