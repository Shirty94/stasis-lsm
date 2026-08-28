use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // copy vmlinux.h into project for clangd
    let vmlinux_source = vmlinux::include_path_root().join(&arch).join("vmlinux.h");
    let dest_dir = manifest_dir.join("src/bpf/include");
    let dest_path = dest_dir.join("vmlinux.h");
    fs::create_dir_all(&dest_dir).unwrap();
    fs::copy(&vmlinux_source, &dest_path).unwrap();

    let vmlinux_local_path = "src/bpf/include".to_string();

    // find libbpf include path
    let libbpf_include = pkg_config::probe_library("libbpf")
        .expect("libbpf not found via pkg-config")
        .include_paths
        .into_iter()
        .next()
        .expect("no include paths found for libbpf")
        .to_str()
        .unwrap()
        .to_owned();

    // build the skeleton
    let skel_path = manifest_dir.join("src/bpf/stasis_lsm.skel.rs");
    SkeletonBuilder::new()
        .source("src/bpf/stasis_lsm.bpf.c")
        .clang_args(["-I", &vmlinux_local_path, "-I", &libbpf_include])
        .build_and_generate(skel_path)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf/stasis_lsm.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/include/vmlinux.h");
}
