mod bpf {
    include!("bpf/stasis_lsm.skel.rs");
}
use bpf::*;

use libbpf_rs::{
    OpenObject,
    skel::{OpenSkel, SkelBuilder, Skel},
};
use std::mem::MaybeUninit;

use plain::Plain;

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

    let skel_builder = StasisLsmSkelBuilder::default();

    let mut open_obj = MaybeUninit::<OpenObject>::uninit();

    let open_skel = skel_builder.open(&mut open_obj)?;

    let mut skel = open_skel.load()?;

    skel.attach()?;

    let _rb_map = &skel.maps.pid_ringbuf;

    let mut rb_builder = libbpf_rs::RingBufferBuilder::new();

    rb_builder.add(&skel.maps.pid_ringbuf, |data| {
        // sanity check
        if data.len() != std::mem::size_of::<FileOpenSample>() {
            eprintln!("Unexpected data size: {}", data.len());
            return -1;
        }

        let sample: FileOpenSample = *plain::from_bytes(data)
            .expect("Failed to parse FileOpenSample");

        // Convert the path byte array to a Rust &str
        let path_len = sample.path.iter()
            .position(|&b| b == 0)
            .unwrap_or(sample.path.len());
        let path_str = std::str::from_utf8(&sample.path[..path_len])
            .unwrap_or("<invalid UTF-8>");

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
