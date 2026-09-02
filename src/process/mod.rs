use crate::suspicion::{self, Decision, EvaluationMetrics};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::{sync::mpsc, task::AbortHandle};

#[derive(Debug)]
pub enum BpfCommand {
    WhitelistAdd { pid: u32, value: u32 },
    WhitelistRemove { pid: u32 },
}

#[derive(Debug)]
pub enum ProcessState {
    /// Process is not currently being tracked or has had its monitoring window expire.
    Idle,

    /// We are actively profiling this process. Holds the handle to the background
    /// timer task so we can abort it if the process dies or is blacklisted.
    Monitoring {
        abort_handle: AbortHandle,
        deadline: Instant,
    },

    /// The monitoring window finished, and we are currently computing the suspicion
    /// score. New events are ignored until evaluation is complete to prevent race conditions.
    EvaluationPending,

    /// The process is trusted.
    /// - `Some(expiry)`: Temporarily whitelisted (eBPF counter is active).
    /// - `None`: Permanently whitelisted (eBPF is bypassing completely).
    Whitelisted { expiry: Option<Instant> },

    /// The process triggered an alert. It will remain in this state until explicit
    /// administrator intervention. We track the next time we should re-alert to prevent flood.
    Alerted {
        cooldown_until: Instant,
        alert_count: u32,
    },
}

pub struct ProcessContext {
    pub _pid: u32,
    pub state: Mutex<ProcessState>,
    // AtomicU32 for safe async incrementing
    pub file_open_count: AtomicU32,
    // future metrics:
    // pub opened_extensions: DashSet<String>,
    // pub unique_directories: DashSet<PathBuf>,
}

impl ProcessContext {
    pub fn new(_pid: u32) -> Self {
        Self {
            _pid,
            state: Mutex::new(ProcessState::Idle),
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
