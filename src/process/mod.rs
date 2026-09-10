use crate::suspicion::{self, Decision, EvaluationMetrics};
use crate::tui::UiEvent;
use dashmap::DashMap;
use std::{
    collections::HashSet,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
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
    pub comm: Mutex<String>,
    pub file_open_count: AtomicU32,
    pub file_write_count: AtomicU32,
    pub file_unlink_count: AtomicU32,
    pub opened_paths: Mutex<Vec<String>>,
}

impl ProcessContext {
    pub fn new(_pid: u32, comm: String) -> Self {
        Self {
            _pid,
            state: Mutex::new(ProcessState::Idle),
            comm: Mutex::new(comm),
            file_open_count: AtomicU32::new(0),
            file_write_count: AtomicU32::new(0),
            file_unlink_count: AtomicU32::new(0),
            opened_paths: Mutex::new(Vec::new()),
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
    pub fn handle_file_open(&self, pid: u32, comm: String, path: String) -> bool {
        let context = self
            .processes
            .entry(pid)
            .or_insert_with(|| {
                let real_path = std::fs::read_link(format!("/proc/{}/exe", pid))
                    .ok()
                    .and_then(|p| p.to_str().map(|s| s.to_string()))
                    .unwrap_or(comm);

                Arc::new(ProcessContext::new(pid, real_path))
            })
            .clone();

        // Always record the path being accessed
        context.opened_paths.lock().unwrap().push(path);

        let display_comm = context.comm.lock().unwrap().clone();
        let mut state = context.state.lock().unwrap();

        match *state {
            ProcessState::Idle => {
                let monitor_duration = Duration::from_secs(1);
                let deadline = Instant::now() + monitor_duration;

                let tracker = self.clone();
                let join_handle = tokio::spawn(async move {
                    tokio::time::sleep(monitor_duration).await;
                    tracker.evaluate(pid);
                });

                *state = ProcessState::Monitoring {
                    _abort_handle: join_handle.abort_handle(),
                    _deadline: deadline,
                };

                context.file_open_count.store(1, Ordering::Relaxed);
                self.update_ui_proc(pid, &display_comm, "Monitoring", 1);
                true
            }

            ProcessState::Monitoring { .. } => {
                context.file_open_count.fetch_add(1, Ordering::Relaxed);
                true
            }

            ProcessState::EvaluationPending => {
                let count = context.file_open_count.load(Ordering::Relaxed);
                self.update_ui_proc(pid, &display_comm, "Evaluation Pending", count);
                false
            }

            ProcessState::Whitelisted { expiry } => {
                if let Some(expiry_time) = expiry {
                    if Instant::now() >= expiry_time {
                        let monitor_duration = Duration::from_secs(1);
                        let deadline = Instant::now() + monitor_duration;

                        let tracker = self.clone();
                        let join_handle = tokio::spawn(async move {
                            tokio::time::sleep(monitor_duration).await;
                            tracker.evaluate(pid);
                        });

                        *state = ProcessState::Monitoring {
                            _abort_handle: join_handle.abort_handle(),
                            _deadline: deadline,
                        };

                        context.file_open_count.store(1, Ordering::Relaxed);
                        self.update_ui_proc(pid, &display_comm, "Monitoring", 1);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            ProcessState::Alerted {
                ref mut cooldown_until,
                ref mut alert_count,
            } => {
                let count = context.file_open_count.load(Ordering::Relaxed);
                if Instant::now() >= *cooldown_until {
                    *alert_count += 1;
                    *cooldown_until = Instant::now() + Duration::from_secs(5);
                    self.ui_log(
                        "ALERT",
                        format!(
                            "PID {} ({}) still misbehaving! (Alert Count: {})",
                            pid, display_comm, alert_count
                        ),
                    );
                }
                self.update_ui_proc(pid, &display_comm, "Alerted", count);
                true
            }
        }
    }

    pub fn handle_file_write(&self, pid: u32, comm: String, path: String) {
        if let Some(context) = self.processes.get(&pid) {
            context.file_write_count.fetch_add(1, Ordering::Relaxed);
            context.opened_paths.lock().unwrap().push(path);
        } else {
            // self-healing initialization for processes already active
            self.handle_file_open(pid, comm, path);
        }
    }

    pub fn handle_file_unlink(&self, pid: u32, comm: String, path: String) {
        if let Some(context) = self.processes.get(&pid) {
            context.file_unlink_count.fetch_add(1, Ordering::Relaxed);
            context.opened_paths.lock().unwrap().push(path);
        } else {
            self.handle_file_open(pid, comm, path);
        }
    }

    /// Run evaluation when the monitoring timer expires.
    fn evaluate(&self, pid: u32) {
        let context = match self.processes.get(&pid) {
            Some(ctx) => ctx.clone(),
            None => return,
        };

        let comm = context.comm.lock().unwrap().clone();
        let mut state = context.state.lock().unwrap();

        if let ProcessState::Monitoring { .. } = *state {
            *state = ProcessState::EvaluationPending;
            drop(state); // drop guard during the evaluation

            let open_count = context.file_open_count.swap(0, Ordering::Relaxed);
            let write_count = context.file_write_count.swap(0, Ordering::Relaxed);
            let unlink_count = context.file_unlink_count.swap(0, Ordering::Relaxed);

            // Extract and clear path collections
            let paths = {
                let mut guard = context.opened_paths.lock().unwrap();
                std::mem::take(&mut *guard)
            };

            self.update_ui_proc(pid, &comm, "Evaluating", open_count);

            // Compute structural metrics
            let mut unique_dirs = HashSet::new();
            let mut hvt_count = 0;

            for p_str in &paths {
                let path = Path::new(p_str);
                if let Some(parent) = path.parent() {
                    unique_dirs.insert(parent.to_path_buf());
                }

                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = ext.to_lowercase();
                    match ext_lower.as_str() {
                        "docx" | "doc" | "pdf" | "xls" | "xlsx" | "ppt" | "pptx" | "odt"
                        | "txt" | "zip" | "tar" | "gz" | "7z" | "rar" | "png" | "jpg" | "jpeg"
                        | "mp4" | "sql" | "db" | "sqlite" | "key" | "pem" | "crt" => {
                            hvt_count += 1;
                        }
                        _ => {}
                    }
                }
            }

            let metrics = EvaluationMetrics {
                file_open_count: open_count,
                file_write_count: write_count,
                file_unlink_count: unlink_count,
                unique_directories: unique_dirs.len() as u32,
                high_value_extension_count: hvt_count,
                duration: Duration::from_secs(1),
            };

            let eval_res = suspicion::evaluate(&metrics);

            let mut state = context.state.lock().unwrap();

            if !self.processes.contains_key(&pid) {
                return;
            }

            // create a structured diagnostic breakdown string for debugging
            let breakdown: Vec<String> = eval_res
                .scores
                .iter()
                .map(|s| format!("{}: {:.2} (wt: {:.1})", s.name, s.score, s.weight))
                .collect();
            let diagnostic_log = format!(
                "PID {} ({}) Evaluation: Score={:.2}, Metrics=[opens: {}, writes: {}, unlinks: {}, dirs: {}, hvts: {}]. Breakdown: [{}]",
                pid,
                comm,
                eval_res.final_score,
                metrics.file_open_count,
                metrics.file_write_count,
                metrics.file_unlink_count,
                metrics.unique_directories,
                metrics.high_value_extension_count,
                breakdown.join(" | ")
            );

            match eval_res.decision {
                Decision::KeepMonitoring => {
                    *state = ProcessState::Idle;
                    self.ui_log("WARN", format!("Doubtful activity. {}", diagnostic_log));
                    self.update_ui_proc(pid, &comm, "Idle", 0);
                }
                Decision::WhitelistTemp { duration } => {
                    let expiry = Instant::now() + duration;
                    *state = ProcessState::Whitelisted {
                        expiry: Some(expiry),
                    };

                    if self.processes.contains_key(&pid) {
                        let _ = self.bpf_tx.try_send(BpfCommand::WhitelistAdd {
                            pid,
                            comm: comm.to_string(),
                            value: 0,
                        });

                        self.ui_log(
                            "INFO",
                            format!(
                                "Whitelisting (temp). Details: {}",
                                diagnostic_log
                            ),
                        );
                        self.update_ui_proc(pid, &comm, "Whitelisted (Temp)", 0);

                        let tracker = self.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(duration).await;
                            tracker.expire_whitelist(pid, expiry);
                        });
                    }
                }
                Decision::Alert => {
                    let cooldown_until = Instant::now() + Duration::from_secs(5);
                    *state = ProcessState::Alerted {
                        cooldown_until,
                        alert_count: 1,
                    };
                    self.ui_log("ALERT", format!("THREAT DETECTED! {}", diagnostic_log));
                    self.update_ui_proc(pid, &comm, "Alerted", open_count);
                }
            }
        }
    }

    /// Actively transitions an expired whitelist back to Idle and evicts it from kernel space.
    fn expire_whitelist(&self, pid: u32, expected_expiry: Instant) {
        if let Some(context) = self.processes.get(&pid) {
            let comm = context.comm.lock().unwrap().clone();
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
                    self.update_ui_proc(pid, &comm, "Idle", 0);
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
            // ensure BPF map entries and TUI entries are removed
            let _ = self.bpf_tx.try_send(BpfCommand::WhitelistRemove { pid });
            let _ = self.ui_tx.try_send(UiEvent::ProcessExited { pid });

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
            let context = Arc::new(ProcessContext::new(pid, path.clone()));
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
            let context = Arc::new(ProcessContext::new(pid, path.clone()));
            self.processes.insert(pid, context);

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
        let context = Arc::new(ProcessContext::new(pid, name.to_string()));
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

    // /// Returns a list of PIDs currently temporarily whitelisted in userspace
    // pub fn get_temp_whitelisted_pids(&self) -> Vec<u32> {
    //     self.processes
    //         .iter()
    //         .filter(|r| {
    //             let state = r.value().state.lock().unwrap();
    //             matches!(*state, ProcessState::Whitelisted { expiry: Some(_) })
    //         })
    //         .map(|r| *r.key())
    //         .collect()
    // }
}
