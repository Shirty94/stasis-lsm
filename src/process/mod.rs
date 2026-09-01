use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub struct ProcessState {
    pub _pid: u32,
    // AtomicU32 for safe async incrementing
    pub file_open_count: AtomicU32,
    // future metrics:
    // pub opened_extensions: DashSet<String>,
    // pub unique_directories: DashSet<PathBuf>,
}

impl ProcessState {
    pub fn new(_pid: u32) -> Self {
        Self {
            _pid,
            file_open_count: AtomicU32::new(0),
        }
    }
}

#[derive(Clone)]
pub struct ProcessTracker {
    // sharded map to track processes
    processes: Arc<DashMap<u32, Arc<ProcessState>>>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            processes: Arc::new(DashMap::new()),
        }
    }

    /// Increments the file open counter for a given PID.
    /// If the PID is not yet tracked, it initializes its state.
    pub fn increment_open_count(&self, pid: u32) -> u32 {
        // Get the process state, or insert a new one if it doesn't exist
        let state = self.processes.entry(pid)
            .or_insert_with(|| Arc::new(ProcessState::new(pid)))
            .clone();

        // increment and return the new count
        state.file_open_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Clean up process state when a process terminates
    pub fn _remove_process(&self, pid: u32) {
        self.processes.remove(&pid);
    }
}
