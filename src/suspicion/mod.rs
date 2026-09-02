use std::time::Duration;

const MIN_WHITELIST_SECS: u64 = 10;
const MAX_WHITELIST_SECS: u64 = 45;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Keep monitoring the process for another window.
    KeepMonitoring,
    /// Temporarily trust the process.
    WhitelistTemp { duration: Duration },
    /// Alert the administrator.
    Alert,
}

/// Extensible structure for holding metrics gathered during the monitoring window.
pub struct EvaluationMetrics {
    pub file_open_count: u32,
    pub duration: Duration,
}

/// Evaluates metrics to produce a bounded decision.
pub fn evaluate(metrics: &EvaluationMetrics) -> Decision {
    let rate = metrics.file_open_count as f32 / metrics.duration.as_secs_f32();

    // rudimentary heuristics:
    if rate > 100.0 {
        // high rate of file opens
        Decision::Alert
    } else if rate < 10.0 {
        // choose random duration between 10 and 45 seconds
        let secs = rand::random_range(MIN_WHITELIST_SECS..=MAX_WHITELIST_SECS);

        // very low filesystem activity -> temporarily whitelist
        Decision::WhitelistTemp {
            duration: Duration::from_secs(secs),
        }
    } else {
        // gray zone -> keep monitoring
        Decision::KeepMonitoring
    }
}
