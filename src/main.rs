mod bpf;
mod process;
mod suspicion;

use bpf::FileOpenSample;
use process::{BpfCommand, ProcessTracker};

use libbpf_rs::{
    MapCore, OpenObject,
    skel::{OpenSkel, Skel, SkelBuilder},
};
use std::{mem::MaybeUninit, sync::Arc};
use tokio::sync::{Semaphore, mpsc};

/// limits CPU and I/O contention (e.g. if heuristics need to read
/// files to check entropy). At ~1KB per task state-machine, 1000
/// tasks consume only ~1MB of RAM.
const MAX_TASKS: usize = 1000;

/// capacity of the event queue.
///
/// sized to absorb massive filesystem spikes (e.g. ransomware
/// encrypting 15,000 files/sec). 65536 events * 272 bytes per event
/// = ~18 MB maximum memory allocation.  This guarantees we can
/// buffer ~2 seconds of extreme activity without dropping events.
const QUEUE_CAPACITY: usize = 65_536;

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

    // leak the OpenObject to make it static
    let open_obj = Box::leak(Box::new(MaybeUninit::<OpenObject>::uninit()));
    let open_skel = skel_builder.open(open_obj)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    // leak the skeleton itself so references to its maps are static
    let skel = Box::leak(Box::new(skel));

    // populate BPF map with ignored prefixes
    let ignored_prefixes_map = &skel.maps.ignored_prefixes;
    for (i, path_pfx) in ignored_paths.iter().enumerate() {
        let mut value = [0u8; 256];
        value[..path_pfx.len()].copy_from_slice(path_pfx.as_bytes());
        let key = (i as u32).to_ne_bytes();
        ignored_prefixes_map.update(&key, &value, libbpf_rs::MapFlags::ANY)?;
    }

    // set up channel for writing commands to the BPF maps
    let (bpf_tx, mut bpf_rx) = mpsc::channel::<BpfCommand>(1024);

    // set up async channel to send events from bpf callback to tokio
    let (tx, mut rx) = mpsc::channel::<FileOpenSample>(QUEUE_CAPACITY);

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

        if let Err(e) = tx.try_send(sample) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    eprintln!("[WARN] Event queue full! Dropping event to prevent OOM.");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    return -1; // channel closed, stop polling ring buffer
                }
            }
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

    let process_tracker = ProcessTracker::new(bpf_tx);

    // move the skeleton into a blocking task that runs the BPF
    // command loop. This keeps the skeleton alive in memory while
    // cleanly executing kernel updates.
    tokio::task::spawn_blocking(move || {
        let whitelist_map = &skel.maps.whitelist;

        while let Some(cmd) = bpf_rx.blocking_recv() {
            match cmd {
                BpfCommand::WhitelistAdd { pid, value } => {
                    let key = pid.to_ne_bytes();
                    let val = value.to_ne_bytes();
                    if let Err(e) = whitelist_map.update(&key, &val, libbpf_rs::MapFlags::ANY) {
                        eprintln!(
                            "[ERROR] Failed to update BPF whitelist for PID {}: {:?}",
                            pid, e
                        );
                    }
                }
                BpfCommand::WhitelistRemove { pid } => {
                    let key = pid.to_ne_bytes();
                    // we try to delete the entry. If the tripwire already deleted it,
                    // bpf_d_path or LSM might have caused an early deletion.
                    // Thus, we safely ignore the NotFound error.
                    if let Err(e) = whitelist_map.delete(&key) {
                        if e.kind() != libbpf_rs::ErrorKind::NotFound {
                            eprintln!(
                                "[ERROR] Failed to delete BPF whitelist for PID {}: {:?}",
                                pid, e
                            );
                        }
                    }
                }
            }
        }
    });

    let analysis_semaphore = Arc::new(Semaphore::new(MAX_TASKS));

    println!("Stasis LSM engine started. Listening for events...");

    while let Some(sample) = rx.recv().await {
        // acquire a permit. If MAX_TASKS tasks are running, this line
        // blocks asynchronously (without blocking the thread) until
        // one of the active tasks finishes.
        let permit = analysis_semaphore.clone().acquire_owned().await?;
        let tracker = process_tracker.clone();

        tokio::spawn(async move {
            // move the permit inside the task
            let _permit = permit;

            let pid = sample.pid;

            // returns true if we should analyze.
            if tracker.handle_file_open(pid) {
                let path_str = sample.path_str();
                println!("[DBG] PID {} opened {}", pid, path_str);

                // TODO: run heuristic checks
            }
        });
    }

    Ok(())
}
