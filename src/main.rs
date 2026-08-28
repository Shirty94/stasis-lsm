mod bpf {
    include!("bpf/stasis_lsm.skel.rs");
}
use bpf::*;

use libbpf_rs::{
    MapCore, OpenObject,
    skel::{OpenSkel, Skel, SkelBuilder},
};
use plain::Plain;
use std::mem::MaybeUninit;

// mirroring the C-struct
#[repr(C)]
#[derive(Clone, Copy)]
struct FileOpenSample {
    pid: u32,
    flags: u32,
    timestamp: u64,
    path: [u8; 256],
}

unsafe impl Plain for FileOpenSample {}

fn main() -> anyhow::Result<()> {
    // extensible vector of ignored paths
    let mut _ignored_paths: Vec<&str> = vec![
        "/tmp",
        "/dev",
        "/var/cache",
        "anon_inode:",
        "/mnt/c", // ignore WSL stuff for now
    ];

    let skel_builder = StasisLsmSkelBuilder::default();

    let mut open_obj = MaybeUninit::<OpenObject>::uninit();
    let open_skel = skel_builder.open(&mut open_obj)?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let ignored_prefixes_map = &skel.maps.ignored_prefixes;

    for (i, path_pfx) in _ignored_paths.iter().enumerate() {
        let mut value = [0u8; 256];
        value[..path_pfx.len()].copy_from_slice(path_pfx.as_bytes());

        // array maps use a 32-bit integer as the key/index
        let key = (i as u32).to_ne_bytes();

        ignored_prefixes_map.update(&key, &value, libbpf_rs::MapFlags::ANY)?;
    }

    let rb_map = &skel.maps.event_rb;

    let mut rb_builder = libbpf_rs::RingBufferBuilder::new();

    rb_builder.add(rb_map, |data| {
        // sanity check
        if data.len() != std::mem::size_of::<FileOpenSample>() {
            eprintln!("Unexpected data size: {}", data.len());
            return -1;
        }

        let sample: FileOpenSample =
            *plain::from_bytes(data).expect("Failed to parse FileOpenSample");

        // convert the path byte array to a Rust &str
        let path_len = sample
            .path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sample.path.len());
        let path_str = std::str::from_utf8(&sample.path[..path_len]).unwrap_or("<invalid UTF-8>");

        println!(
            "PID {} opened {} (flags 0x{:x}) at {}",
            sample.pid, path_str, sample.flags, sample.timestamp
        );

        0 // success
    })?;

    let ringbuf = rb_builder.build()?;

    loop {
        ringbuf.poll(std::time::Duration::from_millis(100))?;
    }
}
