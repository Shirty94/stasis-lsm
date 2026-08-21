use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    // Correct path from vmlinux crate
    let vmlinux_path = vmlinux::include_path_root()
        .join(arch)
        .to_str()
        .unwrap()
        .to_owned();

    SkeletonBuilder::new()
        .source("src/bpf/stasis_lsm.bpf.c")
        .clang_args(["-I", &vmlinux_path])   // ONLY this include, no system headers
        .build_and_generate(out_dir.join("stasis_lsm.skel.rs"))
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf/stasis_lsm.bpf.c");
}
