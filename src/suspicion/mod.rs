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

/// Rich metrics gathered from both eBPF events and userspace analysis.
/// This structure can easily grow without breaking existing heuristics.
pub struct EvaluationMetrics {
    pub file_open_count: u32,
    pub file_write_count: u32,
    pub file_unlink_count: u32,
    pub unique_directories: u32,
    pub high_value_extension_count: u32,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct HeuristicScore {
    pub name: &'static str,
    pub score: f32,
    pub weight: f32,
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub decision: Decision,
    pub final_score: f32,
    pub scores: Vec<HeuristicScore>,
}

pub trait Heuristic: Send + Sync {
    /// Friendly name for logging/debugging
    fn name(&self) -> &'static str;

    /// Evaluates the metrics and returns a suspicion score from 0.0 (safe) to 1.0 (malicious).
    fn evaluate(&self, metrics: &EvaluationMetrics) -> f32;
}

// ==========================================
// HEURISTIC IMPLEMENTATIONS
// ==========================================

/// File Open Rate Heuristic
/// Ransomware must open thousands of user files rapidly to encrypt them.
struct OpenRateHeuristic;
impl Heuristic for OpenRateHeuristic {
    fn name(&self) -> &'static str {
        "File Open Rate"
    }

    fn evaluate(&self, metrics: &EvaluationMetrics) -> f32 {
        let rate = metrics.file_open_count as f32 / metrics.duration.as_secs_f32();

        if rate > 600.0 {
            1.0
        } else if rate > 300.0 {
            0.6
        } else if rate > 50.0 {
            0.2
        } else {
            0.0
        }
    }
}

/// Directory Dispersion Heuristic
/// Standard applications usually read files out of a localized directory (e.g. project files, assets).
/// Ransomware iterates broad directory trees, opening files across many distinct folders.
struct DirectoryDispersionHeuristic;
impl Heuristic for DirectoryDispersionHeuristic {
    fn name(&self) -> &'static str {
        "Directory Dispersion"
    }

    fn evaluate(&self, metrics: &EvaluationMetrics) -> f32 {
        if metrics.unique_directories > 15 {
            1.0 // sifting through broad, nested systems (highly suspicious)
        } else if metrics.unique_directories > 5 {
            0.6
        } else if metrics.unique_directories > 2 {
            0.2
        } else {
            0.0
        }
    }
}

/// High Value Target (HVT) File Type Heuristic
/// Analyzes whether the targeted files are highly critical items (docs, backups, keys) versus system files.
struct HighValueTargetHeuristic;
impl Heuristic for HighValueTargetHeuristic {
    fn name(&self) -> &'static str {
        "High Value Targets"
    }

    fn evaluate(&self, metrics: &EvaluationMetrics) -> f32 {
        if metrics.file_open_count < 5 {
            return 0.0; // avoid mathematical noise on tiny open batches
        }

        let ratio = metrics.high_value_extension_count as f32 / metrics.file_open_count as f32;
        if ratio > 0.8 {
            1.0 // almost exclusively opening user documents/keys
        } else if ratio > 0.5 {
            0.6
        } else if ratio > 0.2 {
            0.2
        } else {
            0.0
        }
    }
}

/// Read-Write Asymmetry Heuristic
/// Standard applications are highly asymmetric (e.g., Loggers write a lot but never delete;
/// Readers open a lot but never write). Ransomware exhibits a strict, balanced loop of
/// opening a file, writing a modified copy, and deleting the original.
struct ReadWriteAsymmetryHeuristic;
impl Heuristic for ReadWriteAsymmetryHeuristic {
    fn name(&self) -> &'static str {
        "Read-Write Asymmetry"
    }

    fn evaluate(&self, metrics: &EvaluationMetrics) -> f32 {
        let total_mods = metrics.file_write_count + metrics.file_unlink_count;

        // quiet process, skip evaluation
        if total_mods < 5 {
            return 0.0;
        }

        // calculate the ratio of file modifications to file opens
        let ratio = total_mods as f32 / (metrics.file_open_count as f32).max(1.0);

        // ransomware typically maintains a ratio close to 1.0 - 2.0 (1 open, 1 write, 1 delete)
        if ratio >= 0.7 && ratio <= 2.5 {
            if metrics.file_unlink_count > 15 {
                1.0 // massive balanced deletions and writes (active encryption sweep)
            } else if metrics.file_unlink_count > 5 {
                0.7 // suspicious write-delete activity
            } else {
                0.3 // mild write-delete activity (e.g. standard file saving)
            }
        } else if metrics.file_unlink_count > 20 {
            // high deletion rate even if opens/writes don't perfectly align (e.g. pure destructive wipers)
            0.8
        } else {
            0.0 // highly imbalanced activity (typical of compilers or databases)
        }
    }
}

// ==========================================
// AGGREGATION ENGINE
// ==========================================

/// Structural configurations for our heuristics engine
struct HeuristicRegistration {
    heuristic: Box<dyn Heuristic>,
    weight: f32, // relative influence of this heuristic on final score (0.0 to 1.0)
}

pub fn evaluate(metrics: &EvaluationMetrics) -> EvaluationResult {
    let registry: Vec<HeuristicRegistration> = vec![
        HeuristicRegistration {
            heuristic: Box::new(OpenRateHeuristic),
            weight: 0.3,
        },
        HeuristicRegistration {
            heuristic: Box::new(DirectoryDispersionHeuristic),
            weight: 0.2,
        },
        HeuristicRegistration {
            heuristic: Box::new(HighValueTargetHeuristic),
            weight: 0.2,
        },
        HeuristicRegistration {
            heuristic: Box::new(ReadWriteAsymmetryHeuristic),
            weight: 0.3,
        },
    ];

    let mut scores = Vec::new();
    let mut total_score = 0.0;
    let mut total_weight = 0.0;

    for reg in &registry {
        let score = reg.heuristic.evaluate(metrics);
        total_score += score * reg.weight;
        total_weight += reg.weight;

        scores.push(HeuristicScore {
            name: reg.heuristic.name(),
            score,
            weight: reg.weight,
        });
    }

    // normalized aggregate suspicion score (0.0 to 1.0)
    let final_suspicion = if total_weight > 0.0 {
        total_score / total_weight
    } else {
        0.0
    };

    let decision = if final_suspicion >= 0.5 {
        Decision::Alert
    } else if final_suspicion < 0.1 {
        // verified safe/dormant -> temporarily whitelist
        let secs = rand::random_range(MIN_WHITELIST_SECS..=MAX_WHITELIST_SECS);

        // very low filesystem activity -> temporarily whitelist
        Decision::WhitelistTemp {
            duration: Duration::from_secs(secs),
        }
    } else {
        // gray zone (between 0.1 and 0.5) -> keep monitoring
        Decision::KeepMonitoring
    };

    EvaluationResult {
        decision,
        final_score: final_suspicion,
        scores,
    }
}
