use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

fn main() {
    build_bpf_file("intercept_only", "src/bpf/intercept_only.bpf.c");
    build_bpf_file("intercept_and_count", "src/bpf/intercept_and_count.bpf.c");
    build_bpf_file("count_syscalls", "src/bpf/count_syscalls.bpf.c");
    build_bpf_file("save_info", "src/bpf/save_info.bpf.c");
    build_bpf_file("save_io", "src/bpf/save_io.bpf.c");
    build_bpf_file("uprobes", "src/bpf/uprobes.bpf.c");
    build_bpf_file("tracer", "src/bpf/tracer.bpf.c");
    build_bpf_file("pin_maps", "src/bpf/pin_maps.bpf.c");
}

fn build_bpf_file(bpf_file: &str, file_name: &str) {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push(format!("{}.skel.rs", bpf_file));

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    // SkeletonBuilder::new()
    //     .source(file_name)
    //     .clang_args([OsStr::new("-I"),Path::new("../../../vmlinux").join(match arch.as_ref() {
    //                 "aarch64" => "arm64",
    //                 "loongarch64" => "loongarch",
    //                 "powerpc64" => "powerpc",
    //                 "riscv64" => "riscv",
    //                 "x86_64" => "x86",
    //                 _ => &arch,
    //             }).as_os_str()
    //     ])
    //     .build_and_generate(&out)
    //     .expect("bpf compilation failed");
    // println!("cargo:rerun-if-changed={}", file_name);

    SkeletonBuilder::new()
        .source(&file_name)
        .clang_args([OsStr::new("-I"),
            OsStr::new(&arch)]
        )
        .build_and_generate(out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", file_name);
}
