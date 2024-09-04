use anyhow::Result;
use std::env;

mod auxiliary;
mod count_syscalls;
mod intercept_and_count;
mod intercept_only;
mod save_info;
mod save_io;
mod uprobes;
mod tracer;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let pids_file = &args[1];

    let tracing_type = &args[2];

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
            uprobes::run_tracing(pids, pid_count, containers, functions)
                .expect("Something went wrong with save_io \n");
        }
        "tracer" => {

            let functions_file = &args[3];

            functions = auxiliary::read_names_from_file(&functions_file)
                .unwrap()
                .clone();
    
    
            if args.len() == 6{
                let filename_for_container_names = &args[4];
    
                containers = auxiliary::read_names_from_file(filename_for_container_names)
                .unwrap()
                .clone();
            }

            let binary_path = args[5].to_string();
            tracer::run_tracing(pids, pid_count, containers, functions,binary_path)
                .expect("Something went wrong with save_io \n");
        }
        _ => {
            println!("Does not match any tracing type");
        }
    }
    Ok(())
}
