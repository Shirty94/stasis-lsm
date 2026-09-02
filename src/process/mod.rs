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
    processes: Arc<DashMap<u32, Arc<ProcessContext>>>,
    bpf_tx: mpsc::Sender<BpfCommand>, // channel sender to write to BPF maps
}

impl ProcessTracker {
    pub fn new(bpf_tx: mpsc::Sender<BpfCommand>) -> Self {
        Self {
            processes: Arc::new(DashMap::new()),
            bpf_tx,
        }
    }

    /// Handles an incoming file open event.
    /// Returns `true` if we should execute active userspace checks (like file entropy).
    pub fn handle_file_open(&self, pid: u32) -> bool {
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
                let join_handle = tokio::spawn(async move {
                    tokio::time::sleep(monitor_duration).await;
                    tracker.evaluate(pid);
                });

                *state = ProcessState::Monitoring {
                    abort_handle: join_handle.abort_handle(),
                    deadline,
                };

                context.file_open_count.store(1, Ordering::Relaxed);
                true
            }

            ProcessState::Monitoring { .. } => {
                context.file_open_count.fetch_add(1, Ordering::Relaxed);
                true
            }

            ProcessState::EvaluationPending => {
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
                        let join_handle = tokio::spawn(async move {
                            tokio::time::sleep(monitor_duration).await;
                            tracker.evaluate(pid);
                        });

                        *state = ProcessState::Monitoring {
                            abort_handle: join_handle.abort_handle(),
                            deadline,
                        };

                        context.file_open_count.store(1, Ordering::Relaxed);
                        true
                    } else {
                        false // bypass remaining analysis
                    }
                } else {
                    false // permanently whitelisted, bypass always
                }
            }
            ProcessState::Alerted {
                ref mut cooldown_until,
                ref mut alert_count,
            } => {
                if Instant::now() >= *cooldown_until {
                    // alert cooldown expired, re-alert. Could maybe
                    // switch this to a background timer, but should
                    // be fine like this, no activity -> no need to
                    // re-alert anyway
                    *alert_count += 1;
                    *cooldown_until = Instant::now() + Duration::from_secs(5);
                    eprintln!(
                        "[RE-ALERT] PID {} still misbehaving! (Alert Count: {})",
                        pid, alert_count
                    );
                }
                true
            }
        }
    }

    /// Run evaluation when the monitoring timer expires.
    fn evaluate(&self, pid: u32) {
        let context = match self.processes.get(&pid) {
            Some(ctx) => ctx.clone(),
            None => return,
        };

        let mut state = context.state.lock().unwrap();

        if let ProcessState::Monitoring { .. } = *state {
            *state = ProcessState::EvaluationPending;
            drop(state); // drop guard during the evaluation

            let count = context.file_open_count.swap(0, Ordering::Relaxed);
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
                    println!(
                        "[INFO] PID {} returned to Idle (gray zone, count: {})",
                        pid, count
                    );
                }
                Decision::WhitelistTemp { duration } => {
                    let expiry = Instant::now() + duration;
                    *state = ProcessState::Whitelisted {
                        expiry: Some(expiry),
                    };

                    // ensure the process wasn't deleted already
                    if self.processes.contains_key(&pid) {
                        let _ = self
                            .bpf_tx
                            .try_send(BpfCommand::WhitelistAdd { pid, value: 0 });

                        let duration_str = format!("{:?}", duration);
                        println!(
                            "[INFO] PID {} dynamically whitelisted for {} seconds",
                            pid, duration_str
                        );

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
                    eprintln!(
                        "[ALERT] PID {} triggered ransomware alert! ({} opens/sec)",
                        pid, count
                    );
                }
            }
        }
    }

    /// Actively transitions an expired whitelist back to Idle and evicts it from kernel space.
    fn expire_whitelist(&self, pid: u32, expected_expiry: Instant) {
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

                    println!("[INFO] PID {} whitelist expired. Returned to Idle.", pid);
                }
            }
        }
    }

    /// Clean up process state when a process terminates
    pub fn remove_process(&self, pid: u32) {
        if let Some((_, context)) = self.processes.remove(&pid) {
            let state = context.state.lock().unwrap();
            if let ProcessState::Monitoring { abort_handle, .. } = &*state {
                abort_handle.abort();
            }
            // ensure we also clean up kernel space maps if the process exits
            let _ = self.bpf_tx.try_send(BpfCommand::WhitelistRemove { pid });
        }
    }
}
