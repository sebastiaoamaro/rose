use anyhow::{bail,Result};
use libbpf_rs::MapFlags;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;
use std::str;

#[repr(C)]
pub struct syscall_op {
    id: i32,
    pid_tgid: u64,
    ret: i32,
    time: u64,
}
#[repr(C)]
pub struct io_op {
    tag: i32,
    pid: i32,
    size: i32,
    buffer: [u8; 64],
}

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn read_numbers_from_file(filename: &str) -> io::Result<Vec<u32>> {
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

pub fn u32_to_u8_array_little_endian(value: u32) -> [u8; 4] {
    [
        value as u8,
        (value >> 8) as u8,
        (value >> 16) as u8,
        (value >> 24) as u8,
    ]
}

pub fn u64_to_u8_array_little_endian(value: u64) -> [u8; 8] {
    [
        value as u8,
        (value >> 8) as u8,
        (value >> 16) as u8,
        (value >> 24) as u8,
        (value >> 32) as u8,
        (value >> 40) as u8,
        (value >> 48) as u8,
        (value >> 56) as u8,
    ]
}

pub fn write_to_file(filename: String, content: String) -> std::io::Result<()> {
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

pub fn collect_trace(syscall_map: &libbpf_rs::Map, io_ops_map: &libbpf_rs::Map, node_count: i32) {
    print!("Collecing trace \n");
    let keys = syscall_map.keys();

    for key in keys {
        let result = syscall_map
            .lookup(&key, MapFlags::ANY)
            .expect("This key is not in syscall_map");

        let sys_op_raw = result.unwrap().clone();

        //println!("Result is {:?}",sys_op);

        unsafe {
            let sys_op: *const syscall_op = sys_op_raw.as_ptr() as *const syscall_op;
            let readable_sys_op: &syscall_op = &*sys_op;

            let pid = (readable_sys_op.pid_tgid >> 32) as u32;

            if readable_sys_op.id == 0 {
                continue;
            }

            //println!("id:{} ret:{} pid_tgid:{} time:{}", readable_sys_op.id, readable_sys_op.ret,pid,readable_sys_op.time);
        }
    }

    let keys = io_ops_map.keys();

    let mut total = 0;
    let mut count = 0;
    for key in keys {
        let result = io_ops_map.lookup(&key, MapFlags::ANY);

        match result {
            Ok(result) => {
                let io_op_raw = result.unwrap().clone();

                unsafe {
                    let io_op: *const io_op = io_op_raw.as_ptr() as *const io_op;
                    let readable_io_op: &io_op = &*io_op;

                    if readable_io_op.tag == 0 {
                        continue;
                    }
                    //let text = buffer_to_string(&readable_io_op.buffer);

                    //println!("tag:{} pid:{} buffer:{:?}", readable_io_op.tag, readable_io_op.pid,text);
                    if readable_io_op.tag == 2 {
                        total += readable_io_op.size;
                    }
                }
                count += 1;
            }
            Err(e) => {
                println!("Err: {:?}", e);
            }
        }
    }

    let average = total / count;
    match write_to_file(
        format!("/tmp/read_average{}", node_count),
        format!("Average:{} \n", average.to_string()),
    ) {
        Ok(_) => println!("File successfully written."),
        Err(e) => eprintln!("Error writing file: {}", e),
    }
}

pub fn buffer_to_string(buffer: &[u8]) -> String {
    let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
    str::from_utf8(&buffer[..len]).unwrap_or("").to_string()
}

pub fn get_overlay2_location(container_name: &str) -> Result<String, io::Error> {
    // Construct the command
    let command = format!(
        "docker container inspect {} | jq -r '.[0].GraphDriver.Data.MergedDir'",
        container_name
    );

    // Execute the command
    let output = Command::new("sh").arg("-c").arg(&command).output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to execute command",
        ));
    }

    // Convert the command output to a String
    let mut response = String::from_utf8_lossy(&output.stdout).to_string();

    // Remove the trailing newline character
    if let Some(pos) = response.rfind('\n') {
        response.truncate(pos);
    }

    Ok(response)
}

pub fn read_names_from_file(filename: &str) -> io::Result<Vec<String>> {
    // Open the file
    let file = File::open(filename)?;
    // Create a buffered reader
    let reader = BufReader::new(file);

    // Collect lines into a vector
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    Ok(lines)
}


pub fn collect_uprobe_stats(uprobe_counters: &libbpf_rs::Map,functions:Vec<String>){
    print!("Collecing uprobe_stats \n");
    let keys = uprobe_counters.keys();

    for key in keys {
        let result = uprobe_counters
            .lookup(&key, MapFlags::ANY)
            .expect("This key is not in uprobe_counters");

        let key_array: [u8; 4] = key.try_into().ok().unwrap();

        let key_value:i32 = i32::from_ne_bytes(key_array);

        let value_array: [u8; 4] = result.unwrap().try_into().ok().unwrap();

        let value:i32 = i32::from_ne_bytes(value_array);

        if value > 0{
            println!("Key is {} and value is {} for function {}",key_value,value,functions.get(key_value as usize).unwrap());
        }
    }
}