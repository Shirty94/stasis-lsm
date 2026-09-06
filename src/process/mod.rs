use crate::suspicion::{self, Decision, EvaluationMetrics};
use crate::tui::UiEvent;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::{sync::mpsc, task::AbortHandle};

const PERM_WHITELIST_VAL: u32 = 0xFFFFFFFF;

#[derive(Debug)]
pub enum BpfCommand {
    WhitelistAdd { pid: u32, comm: String, value: u32 },
    WhitelistRemove { pid: u32 },
}

#[derive(Debug)]
pub enum ProcessState {
    /// Process is not currently being tracked or has had its monitoring window expire.
    Idle,

    /// We are actively profiling this process. Holds the handle to the background
    /// timer task so we can abort it if the process dies or is blacklisted.
    Monitoring {
        _abort_handle: AbortHandle,
        _deadline: Instant,
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
    /// sharded map to track processes
    processes: Arc<DashMap<u32, Arc<ProcessContext>>>,
    bpf_tx: mpsc::Sender<BpfCommand>, // channel sender to write to BPF maps
    ui_tx: mpsc::Sender<UiEvent>,     // UI transmission channel
}

impl ProcessTracker {
    pub fn new(bpf_tx: mpsc::Sender<BpfCommand>, ui_tx: mpsc::Sender<UiEvent>) -> Self {
        Self {
            processes: Arc::new(DashMap::new()),
            bpf_tx,
            ui_tx,
        }
    }

    /// Helper to send logs to the UI without blocking
    fn ui_log(&self, level: &str, msg: String) {
        let _ = self.ui_tx.try_send(UiEvent::Log {
            level: level.to_string(),
            msg,
        });
    }

    /// Helper to update process view in TUI
    fn update_ui_proc(&self, pid: u32, comm: &str, state: &str, count: u32) {
        let _ = self.ui_tx.try_send(UiEvent::ProcessUpdated {
            pid,
            comm: comm.to_string(),
            state: state.to_string(),
            count,
        });
    }

    /// Handles an incoming file open event.
    /// Returns `true` if we should execute active userspace checks (like file entropy).
    pub fn handle_file_open(&self, pid: u32, comm: String) -> bool {
        let context = self
            .processes
            .entry(pid)
            .or_insert_with(|| Arc::new(ProcessContext::new(pid)))
            .clone();

        let mut state = context.state.lock().unwrap();

        match *state {
            ProcessState::Idle => {
                // first event, start monitoring window.
                let monitor_duration = Duration::from_secs(1);
                let deadline = Instant::now() + monitor_duration;

                let tracker = self.clone();
                let comm_clone = comm.clone();
                let join_handle = tokio::spawn(async move {
                    tokio::time::sleep(monitor_duration).await;
                    tracker.evaluate(pid, &comm_clone);
                });

                *state = ProcessState::Monitoring {
                    _abort_handle: join_handle.abort_handle(),
                    _deadline: deadline,
                };

                context.file_open_count.store(1, Ordering::Relaxed);
                self.update_ui_proc(pid, &comm, "Monitoring", 1);
                true
            }

            ProcessState::Monitoring { .. } => {
                let count = context.file_open_count.fetch_add(1, Ordering::Relaxed);
                // self.update_ui_proc(pid, &comm, "Monitoring", count);
                true
            }

            ProcessState::EvaluationPending => {
                let count = context.file_open_count.load(Ordering::Relaxed);
                self.update_ui_proc(pid, &comm, "Evaluation Pending", count);
                // ignore events while calculating evaluation to prevent race conditions.
                false
            }

            ProcessState::Whitelisted { expiry } => {
                if let Some(expiry_time) = expiry {
                    if Instant::now() >= expiry_time {
                        // whitelist expired, transition to monitoring
                        let monitor_duration = Duration::from_secs(1);
                        let deadline = Instant::now() + monitor_duration;

                        let tracker = self.clone();
                        let comm_clone = comm.clone();
                        let join_handle = tokio::spawn(async move {
                            tokio::time::sleep(monitor_duration).await;
                            tracker.evaluate(pid, &comm_clone);
                        });

                        *state = ProcessState::Monitoring {
                            _abort_handle: join_handle.abort_handle(),
                            _deadline: deadline,
                        };

                        context.file_open_count.store(1, Ordering::Relaxed);
                        self.update_ui_proc(pid, &comm, "Monitoring", 1);
                        true
                    } else {
                        let count = context.file_open_count.load(Ordering::Relaxed);
                        //self.update_ui_proc(pid, &comm, "Whitelisted (Temp)", count);
                        false // bypass remaining analysis
                    }
                } else {
                    let count = context.file_open_count.load(Ordering::Relaxed);
                    //self.update_ui_proc(pid, &comm, "Whitelisted (Perm)", count);
                    false // permanently whitelisted, bypass always
                }
            }
            ProcessState::Alerted {
                ref mut cooldown_until,
                ref mut alert_count,
            } => {
                let count = context.file_open_count.load(Ordering::Relaxed);
                if Instant::now() >= *cooldown_until {
                    // alert cooldown expired, re-alert. Could maybe
                    // switch this to a background timer, but should
                    // be fine like this, no activity -> no need to
                    // re-alert anyway
                    *alert_count += 1;
                    *cooldown_until = Instant::now() + Duration::from_secs(5);
                    self.ui_log(
                        "ALERT",
                        format!(
                            "PID {} ({}) still misbehaving! (Alert Count: {})",
                            pid, comm, alert_count
                        ),
                    );
                }
                self.update_ui_proc(pid, &comm, "Alerted", count);
                true
            }
        }
    }

    /// Run evaluation when the monitoring timer expires.
    fn evaluate(&self, pid: u32, comm: &str) {
        let context = match self.processes.get(&pid) {
            Some(ctx) => ctx.clone(),
            None => return,
        };

        let mut state = context.state.lock().unwrap();

        if let ProcessState::Monitoring { .. } = *state {
            *state = ProcessState::EvaluationPending;
            drop(state); // drop guard during the evaluation

            let count = context.file_open_count.swap(0, Ordering::Relaxed);
            self.update_ui_proc(pid, comm, "Evaluating", count);

            let metrics = EvaluationMetrics {
                file_open_count: count,
                duration: Duration::from_secs(1),
            };

            let decision = suspicion::evaluate(&metrics);

            let mut state = context.state.lock().unwrap();
            match decision {
                Decision::KeepMonitoring => {
                    // we reset to Idle, next file_open starts new window
                    *state = ProcessState::Idle;
                    self.ui_log(
                        "INFO",
                        format!(
                            "PID {} ({}) returned to Idle (gray zone, count: {})",
                            pid, comm, count
                        ),
                    );
                    self.update_ui_proc(pid, comm, "Idle", 0);
                }
                Decision::WhitelistTemp { duration } => {
                    let expiry = Instant::now() + duration;
                    *state = ProcessState::Whitelisted {
                        expiry: Some(expiry),
                    };

                    // ensure the process wasn't deleted already
                    if self.processes.contains_key(&pid) {
                        let _ = self.bpf_tx.try_send(BpfCommand::WhitelistAdd {
                            pid,
                            comm: comm.to_string(),
                            value: 0,
                        });

                        self.ui_log(
                            "INFO",
                            format!(
                                "PID {} ({}) dynamically whitelisted for {:?}",
                                pid, comm, duration
                            ),
                        );
                        self.update_ui_proc(pid, comm, "Whitelisted (Temp)", 0);

                        let tracker = self.clone();
                        let comm_clone = comm.to_string();
                        tokio::spawn(async move {
                            tokio::time::sleep(duration).await;
                            tracker.expire_whitelist(pid, &comm_clone, expiry);
                        });
                    }
                }
                Decision::Alert => {
                    let cooldown_until = Instant::now() + Duration::from_secs(5);
                    *state = ProcessState::Alerted {
                        cooldown_until,
                        alert_count: 1,
                    };
                    self.ui_log(
                        "ALERT",
                        format!(
                            "PID {} ({}) triggered ransomware alert! ({} opens/sec)",
                            pid, comm, count
                        ),
                    );
                    self.update_ui_proc(pid, comm, "Alerted", count);
                }
            }
        }
    }

    /// Actively transitions an expired whitelist back to Idle and evicts it from kernel space.
    fn expire_whitelist(&self, pid: u32, comm: &str, expected_expiry: Instant) {
        if let Some(context) = self.processes.get(&pid) {
            let mut state = context.state.lock().unwrap();

            if let ProcessState::Whitelisted {
                expiry: Some(current_expiry),
            } = *state
            {
                // ensure we don't clear a newer whitelist if this
                // process was re-evaluated and whitelisted again
                if current_expiry == expected_expiry {
                    *state = ProcessState::Idle;
                    context.file_open_count.store(0, Ordering::Relaxed);

                    // expire dynamic whitelist entry
                    let _ = self.bpf_tx.try_send(BpfCommand::WhitelistRemove { pid });

                    self.ui_log(
                        "INFO",
                        format!(
                            "PID {} ({}) whitelist expired. Returned to Idle.",
                            pid, comm
                        ),
                    );
                    self.update_ui_proc(pid, comm, "Idle", 0);
                }
            }
        }
    }

    /// Clean up userspace process tracking and abort timers when a PID exits or is replaced
    pub fn handle_process_exit(&self, pid: u32, comm: &str) {
        if let Some((_, context)) = self.processes.remove(&pid) {
            let state = context.state.lock().unwrap();
            if let ProcessState::Monitoring {
                _abort_handle: abort_handle,
                ..
            } = &*state
            {
                abort_handle.abort();
            }
            // ensure BPF map entries are removed
            let _ = self.bpf_tx.try_send(BpfCommand::WhitelistRemove { pid });
            self.ui_log(
                "INFO",
                format!(
                    "PID {} ({}) exited. Cleaned up tracking context.",
                    pid, comm
                ),
            );
        }
    }

    /// Handles process execution. First cleans up stale structures for the recycled PID,
    /// then determines if the program qualifies for a permanent, bypass-all whitelist.
    pub fn handle_process_exec(&self, pid: u32, path: String) {
        // clean up any recycled PID tracking
        self.handle_process_exit(pid, &path);

        // perform static whitelisting checks
        if self.is_permanently_whitelisted(&path) {
            let context = Arc::new(ProcessContext::new(pid));
            {
                let mut state = context.state.lock().unwrap();
                *state = ProcessState::Whitelisted { expiry: None };
            }
            self.processes.insert(pid, context);

            // BPF map bypass (0xFFFFFFFF triggers the permanent path)
            let _ = self.bpf_tx.try_send(BpfCommand::WhitelistAdd {
                pid,
                comm: path.clone(),
                value: PERM_WHITELIST_VAL,
            });

            self.ui_log(
                "INFO",
                format!(
                    "PID {} ({}) matched permanent whitelist. Configured bypass.",
                    pid, path
                ),
            );
            self.update_ui_proc(pid, &path, "Whitelisted (Perm)", 0);
        } else {
            self.ui_log(
                "INFO",
                format!("PID {} ({}) exec'd. Initializing tracking.", pid, path),
            );
            self.update_ui_proc(pid, &path, "Idle", 0);
        }
    }

    /// Check if a binary path is trusted and should never be analyzed
    fn is_permanently_whitelisted(&self, path: &str) -> bool {
        // TODO: actually check the permanent-whitelist
        path.starts_with("/usr/bin/")
            || path.starts_with("/bin/")
            || path.starts_with("/usr/sbin/")
            || path.ends_with("/cargo")
            || path.ends_with("/rustc")
    }

    /// Permanently whitelists a PID in both the userspace tracker and the eBPF map.
    /// This prevents recycled PIDs or early startup events from overwriting trusted states.
    pub fn whitelist_pid_permanently(&self, pid: u32, name: &str) {
        let context = Arc::new(ProcessContext::new(pid));
        {
            let mut state = context.state.lock().unwrap();
            *state = ProcessState::Whitelisted { expiry: None };
        }
        self.processes.insert(pid, context);

        // directly inject permanent whitelist status to the kernel (value = 0xFFFFFFFF)
        let _ = self.bpf_tx.try_send(BpfCommand::WhitelistAdd {
            pid,
            comm: name.to_string(),
            value: PERM_WHITELIST_VAL,
        });
        self.ui_log(
            "INFO",
            format!(
                "PID {} ({}) marked permanently whitelisted in userspace & kernel.",
                pid, name
            ),
        );
        self.update_ui_proc(pid, name, "Idle", 0);
    }

    /// Returns a list of PIDs currently temporarily whitelisted in userspace
    pub fn get_temp_whitelisted_pids(&self) -> Vec<u32> {
        self.processes
            .iter()
            .filter(|r| {
                let state = r.value().state.lock().unwrap();
                matches!(*state, ProcessState::Whitelisted { expiry: Some(_) })
            })
            .map(|r| *r.key())
            .collect()
    }
}
