mod bpf;
mod process;
mod suspicion;
mod tui;

use bpf::EventSample;
use process::{BpfCommand, ProcessTracker};
use tui::{Tui, UiEvent};

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

/// Reads `/proc/self/status` to determine the global (host) PID.
/// This prevents mismatches when running inside PID namespaces (containers/sandboxes/WSL).
fn get_global_pid() -> u32 {
    let status_content = std::fs::read_to_string("/proc/self/status").ok();

    status_content
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("NSpid:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .last()
                        .and_then(|pid_str| pid_str.parse::<u32>().ok())
                })
        })
        .unwrap_or_else(std::process::id)
}

/// A thread-safe wrapper around a static libbpf map reference.
/// BPF maps are inherently thread-safe to query/update concurrently from multiple threads
/// as the Linux kernel manages concurrency internal to the map.
struct SharedMap(&'static libbpf_rs::Map<'static>);
unsafe impl Send for SharedMap {}
unsafe impl Sync for SharedMap {}

impl SharedMap {
    pub fn update(
        &self,
        key: &[u8],
        val: &[u8],
        flags: libbpf_rs::MapFlags,
    ) -> Result<(), libbpf_rs::Error> {
        self.0.update(key, val, flags)
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), libbpf_rs::Error> {
        self.0.delete(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.0.keys()
    }

    pub fn lookup(
        &self,
        key: &[u8],
        flags: libbpf_rs::MapFlags,
    ) -> Result<Option<Vec<u8>>, libbpf_rs::Error> {
        self.0.lookup(key, flags)
    }
}

struct SendRingBuffer<T>(T);
unsafe impl<T> Send for SendRingBuffer<T> {}

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
    let whitelist_map: &'static libbpf_rs::Map<'static> = &skel.maps.whitelist;
    let ignored_prefixes_map: &'static libbpf_rs::Map<'static> = &skel.maps.ignored_prefixes;
    let rb_map: &'static libbpf_rs::Map<'static> = &skel.maps.event_rb;

    // set up channel for tui, bpf map manipulation and bpf events
    let (ui_tx, ui_rx) = mpsc::channel::<UiEvent>(4096);
    let (bpf_tx, mut bpf_rx) = mpsc::channel::<BpfCommand>(1024);
    let (tx, mut rx) = mpsc::channel::<EventSample>(QUEUE_CAPACITY);

    // set up process tracker
    let process_tracker = ProcessTracker::new(bpf_tx, ui_tx.clone());

    // send initial TUI log
    let _ = ui_tx.try_send(UiEvent::Log {
        level: "INFO".to_string(),
        msg: "Stasis Engine starting...".to_string(),
    });

    // add our own PID to the whitelist
    let self_pid = get_global_pid();
    process_tracker.whitelist_pid_permanently(self_pid, "stasis_engine");

    // populate BPF map with ignored prefixes
    for (i, path_pfx) in ignored_paths.iter().enumerate() {
        let mut value = [0u8; 256];
        value[..path_pfx.len()].copy_from_slice(path_pfx.as_bytes());
        let key = (i as u32).to_ne_bytes();
        ignored_prefixes_map.update(&key, &value, libbpf_rs::MapFlags::ANY)?;
    }

    // set up RingBuffer
    let mut rb_builder = libbpf_rs::RingBufferBuilder::new();

    rb_builder.add(rb_map, move |data| {
        // sanity check
        if data.len() != std::mem::size_of::<EventSample>() {
            eprintln!(
                "Unexpected data size: {} (expected {})",
                data.len(),
                std::mem::size_of::<EventSample>()
            );
            return -1;
        }

        let sample: EventSample = *plain::from_bytes(data).expect("Failed to parse FileOpenSample");

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
    let ringbuf = SendRingBuffer(ringbuf);

    let ui_tx_rb = ui_tx.clone();
    tokio::task::spawn_blocking(move || {
        let ringbuf = ringbuf;
        loop {
            if let Err(e) = ringbuf.0.poll(std::time::Duration::from_millis(100)) {
                let _ = ui_tx_rb.try_send(UiEvent::Log {
                    level: "ERROR".to_string(),
                    msg: format!("Error polling ring buffer: {:?}", e),
                });
                break;
            }
        }
    });

    let bpf_whitelist_map = SharedMap(whitelist_map);
    let ui_tx_bpf = ui_tx.clone();
    tokio::task::spawn_blocking(move || {
        while let Some(cmd) = bpf_rx.blocking_recv() {
            match cmd {
                BpfCommand::WhitelistAdd { pid, comm, value } => {
                    let key = pid.to_ne_bytes();
                    let val = value.to_ne_bytes();
                    if let Err(e) = bpf_whitelist_map.update(&key, &val, libbpf_rs::MapFlags::ANY) {
                        let _ = ui_tx_bpf.try_send(UiEvent::Log {
                            level: "ERROR".to_string(),
                            msg: format!("Failed to update BPF whitelist for PID {}: {:?}", pid, e),
                        });
                    } else {
                        let _ = ui_tx_bpf.try_send(UiEvent::BpfWhitelistAdd { pid, comm, value });
                    }
                }
                BpfCommand::WhitelistRemove { pid } => {
                    let key = pid.to_ne_bytes();
                    match bpf_whitelist_map.delete(&key) {
                        Ok(_) => {
                            let _ = ui_tx_bpf.try_send(UiEvent::BpfWhitelistRemove { pid });
                        }
                        Err(e) => {
                            if e.kind() == libbpf_rs::ErrorKind::NotFound {
                                // if kernel tracepoint cleared it first still remove from the UI
                                let _ = ui_tx_bpf.try_send(UiEvent::BpfWhitelistRemove { pid });
                            } else {
                                let _ = ui_tx_bpf.try_send(UiEvent::Log {
                                    level: "ERROR".to_string(),
                                    msg: format!(
                                        "Failed to delete BPF whitelist for PID {}: {:?}",
                                        pid, e
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    });

    std::thread::spawn(move || {
        let tui = Tui::new(ui_rx);
        if let Err(e) = tui.run() {
            eprintln!("TUI run error: {:?}", e);
        }
    });

    // maximum number of parallel tasks for event handling
    let _analysis_semaphore = Arc::new(Semaphore::new(MAX_TASKS));

    while let Some(sample) = rx.recv().await {
        match sample.event_type {
            0 => {
                // EVENT_FILE_OPEN - process state synchronously to guarantee ordering
                let pid = sample.pid;
                let comm_str = sample.comm_str().to_string();

                let _needs_active_analysis = process_tracker.handle_file_open(pid, comm_str);

                // if needs_active_analysis {
                //     // only spawn a task if we need to do heavy active analysis
                //     let permit = analysis_semaphore.clone().acquire_owned().await?;
                //     tokio::spawn(async move {
                //         let _permit = permit;
                //         // future heavy checks go here
                //     });
                // }
            }
            1 => {
                let path = sample.path_str().to_string();
                process_tracker.handle_process_exec(sample.pid, path);
            }
            2 => {
                let comm_str = sample.comm_str().to_string();
                process_tracker.handle_process_exit(sample.pid, &comm_str);
            }
            _ => {}
        }
    }

    Ok(())
}
