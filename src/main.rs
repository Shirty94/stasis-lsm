mod bpf;
mod process;
mod suspicion;

use bpf::FileOpenSample;

use libbpf_rs::{
    MapCore, OpenObject,
    skel::{OpenSkel, Skel, SkelBuilder},
};
use std::mem::MaybeUninit;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // vector of ignored paths
    let ignored_paths: Vec<&str> = vec![
        "/tmp",
        "/dev",
        "/var/cache",
        "anon_inode:",
        "/mnt/c", // ignore WSL stuff for now
    ];

    // initialize eBPF
    let skel_builder = bpf::skeleton::StasisLsmSkelBuilder::default();
    let mut open_obj = MaybeUninit::<OpenObject>::uninit();
    let open_skel = skel_builder.open(&mut open_obj)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    // populate BPF map with ignored prefixes
    let ignored_prefixes_map = &skel.maps.ignored_prefixes;
    for (i, path_pfx) in ignored_paths.iter().enumerate() {
        let mut value = [0u8; 256];
        value[..path_pfx.len()].copy_from_slice(path_pfx.as_bytes());
        let key = (i as u32).to_ne_bytes();
        ignored_prefixes_map.update(&key, &value, libbpf_rs::MapFlags::ANY)?;
    }

    // set up async channel to send events from bpf callback to tokio
    // tx = producer (transmitter), rx = consumer (receiver)
    let (tx, mut rx) = mpsc::unbounded_channel::<FileOpenSample>();

    // set up RingBuffer
    let rb_map = &skel.maps.event_rb;
    let mut rb_builder = libbpf_rs::RingBufferBuilder::new();

    rb_builder.add(rb_map, move |data| {
        // sanity check
        if data.len() != std::mem::size_of::<FileOpenSample>() {
            eprintln!("Unexpected data size: {}", data.len());
            return -1;
        }

        let sample: FileOpenSample =
            *plain::from_bytes(data).expect("Failed to parse FileOpenSample");

        // forward event to the async processor
        if tx.send(sample).is_err() {
            return -1; // channel closed, stop receiving
        }

        0 // success
    })?;

    let ringbuf = rb_builder.build()?;

    tokio::task::spawn_blocking(move || {
        loop {
            if let Err(e) = ringbuf.poll(std::time::Duration::from_millis(100)) {
                eprintln!("Error polling ring buffer: {:?}", e);
                break;
            }
        }
    });

    println!("Stasis LSM engine started. Listening for events...");

    while let Some(sample) = rx.recv().await {
        tokio::spawn(async move {
            let path_str = sample.path_str();
            println!(
                "[DBG] PID {} opened {} at {}",
                sample.pid, path_str, sample.timestamp
            );

            // TODO: run heuristic checks
        });
    }

    Ok(())
}
