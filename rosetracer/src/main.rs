use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::libbpf_sys::BPF_ANY;
use libbpf_rs::MapFlags;
use core::time::Duration;
use std::thread::sleep;
use libbpf_rs::PerfBufferBuilder;
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::fs::File;
use std::io::{self, BufRead};
use std::env;
use std::str;
use std::io::Write;
use std::fs::OpenOptions;

#[repr(C)]
pub struct syscall_op {
	id:i32,
	pid_tgid:u64,
	ret:i32,
	time:u64,
}
#[repr(C)]
pub struct io_op {
	tag:i32,
	pid:i32,
    size:i32,
	buffer:[u8;64],
}

mod trace {
    include!(concat!(env!("OUT_DIR"), "/trace.skel.rs"));
}
use trace::*;

type Event = trace_bss_types::event;
unsafe impl Plain for Event {}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let filename = &args[1];

    let node_count = &args[2];

    let pids = read_numbers_from_file(filename).unwrap().clone();

    println!("Started tracing for \nPids:{:?}",pids);

    let pid_count = pids.len().clone();

    //Build the BPF program
    let mut skel_builder = TraceSkelBuilder::default();

    //skel_builder.obj_builder.debug(true);

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    open_skel.rodata().pid_counter = pid_count as i32;

    let mut skel = open_skel.load()?;

    let _tracepoint_write_enter = skel.progs_mut().trace_write().attach_tracepoint("syscalls", "sys_enter_write")?;

    let _tracepoint_enter_read = skel.progs_mut().trace_read_enter().attach_tracepoint("syscalls", "sys_enter_read")?;

    let _tracepoint_exit_read = skel.progs_mut().trace_read_exit().attach_tracepoint("syscalls", "sys_exit_read")?;

    let _tracepoint_sys_enter = skel.progs_mut().trace_sys_enter().attach_tracepoint("raw_syscalls", "sys_enter")?;

    let _tracepoint_sys_exit = skel.progs_mut().trace_sys_exit().attach_tracepoint("raw_syscalls", "sys_exit")?;


    let _tracepoint_enter_accept = skel.progs_mut().trace_accept_enter().attach_tracepoint("syscalls", "sys_enter_accept")?;

    let _tracepoint_exit_accept = skel.progs_mut().trace_accept_exit().attach_tracepoint("syscalls", "sys_exit_accept")?;

    let _tracepoint_enter_connect = skel.progs_mut().trace_connect_enter().attach_tracepoint("syscalls", "sys_enter_connect")?;

    let _tracepoint_exit_connect = skel.progs_mut().trace_connect_exit().attach_tracepoint("syscalls", "sys_exit_connect")?;

    for (index,pid) in pids.iter().enumerate(){
        let pid_vec = u32_to_u8_array_little_endian(*pid);
        skel.maps_mut().pids().update(&pid_vec, &pid_vec, MapFlags::ANY)?;
    }


    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_secs(1));
    }

    collect_trace(skel.maps().syscalls(),skel.maps().io_ops(),node_count.parse::<i32>().unwrap());

    Ok(())
}

fn read_numbers_from_file(filename: &str) -> io::Result<Vec<u32>> {
    let path = Path::new(filename);
    let file = File::open(&path)?;
    let reader = io::BufReader::new(file);

    let mut numbers = Vec::new();

    for line in reader.lines() {
        let line = line?;
        match line.trim().parse::<u32>() {
            Ok(num) => numbers.push(num),
            Err(e) => eprintln!("Error parsing number '{}': {}", line, e),
        }
    }

    Ok(numbers)
}


fn u32_to_u8_array_little_endian(value: u32) -> [u8; 4] {
    [
        value as u8,
        (value >> 8) as u8,
        (value >> 16) as u8,
        (value >> 24) as u8,
    ]
}

fn write_to_file(filename: String, content: String) -> std::io::Result<()> {
    // Open a file in write mode, creating it if it doesn't exist
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true) // Create the file if it doesn't exist
        .open(filename)?;

    // Write the content to the file
    file.write_all(content.as_bytes())?;

    // Flush the buffer to ensure all data is written to the file
    file.flush()?;

    Ok(())
}

fn collect_trace(syscall_map: &libbpf_rs::Map,io_ops_map:&libbpf_rs::Map,node_count:i32){

    print!("Collecing trace \n");
    let keys = syscall_map.keys();

    for key in keys{
        let result = syscall_map.lookup(&key, MapFlags::ANY).expect("This key is not in syscall_map");

        let sys_op_raw = result.unwrap().clone();

        //println!("Result is {:?}",sys_op);

        unsafe {
            let sys_op: *const syscall_op = sys_op_raw.as_ptr() as *const syscall_op;
            let readable_sys_op: &syscall_op = &*sys_op;

            let pid = (readable_sys_op.pid_tgid >> 32) as u32;

            if readable_sys_op.id == 0{
                continue;
            }
            
            //println!("id:{} ret:{} pid_tgid:{} time:{}", readable_sys_op.id, readable_sys_op.ret,pid,readable_sys_op.time);
        }


    }

    let keys = io_ops_map.keys();

    let mut total = 0;
    let mut count = 0;
    for key in keys{
        let result = io_ops_map.lookup(&key, MapFlags::ANY);

        match result{
            Ok(result) =>{
                let io_op_raw = result.unwrap().clone();
        
                unsafe {
                    let io_op: *const io_op = io_op_raw.as_ptr() as *const io_op;
                    let readable_io_op: &io_op = &*io_op;
                    
                    if readable_io_op.tag == 0{
                        continue;
                    }
                    let text = buffer_to_string(&readable_io_op.buffer);
                    
                    //println!("tag:{} pid:{} buffer:{:?}", readable_io_op.tag, readable_io_op.pid,text);
                    if(readable_io_op.tag == 2){
                        total += readable_io_op.size;
                    }
                }
                count+=1;
            }
            Err(e) => {
                println!("Err: {:?}",e);
            }
        }
    }

    let average = total/count;
    match write_to_file(format!("/tmp/read_average{}",node_count), format!("Total:{} Average:{}",total.to_string(),average.to_string())) {
        Ok(_) => println!("File successfully written."),
        Err(e) => eprintln!("Error writing file: {}", e),
    }

}

fn buffer_to_string(buffer: &[u8]) -> String {
    let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
    str::from_utf8(&buffer[..len]).unwrap_or("").to_string()
}