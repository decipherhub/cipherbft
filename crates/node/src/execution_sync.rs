//! Execution-Consensus synchronization tracking.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tracing::error;

/// Configuration for execution sync tracking.
///
/// Note: Named `ExecutionSyncConfig` to avoid collision with
/// `cipherbft_consensus::ExecutionSyncConfig`.
#[derive(Clone, Debug)]
pub struct ExecutionSyncConfig {
    /// Maximum blocks execution can fall behind before halting.
    pub max_divergence: u64,
    /// Maximum consecutive failures before halting.
    pub max_consecutive_failures: u32,
}

impl Default for ExecutionSyncConfig {
    fn default() -> Self {
        Self {
            max_divergence: 10,
            max_consecutive_failures: 5,
        }
    }
}

/// Action to take after execution failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    Continue,
    Halt { reason: String },
}

/// Tracks execution progress relative to consensus.
pub struct ExecutionSyncTracker {
    last_executed: AtomicU64,
    consecutive_failures: AtomicU32,
    config: ExecutionSyncConfig,
}

impl ExecutionSyncTracker {
    pub fn new(config: ExecutionSyncConfig) -> Self {
        Self {
            last_executed: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            config,
        }
    }

    pub fn on_success(&self, height: u64) {
        self.last_executed.store(height, Ordering::SeqCst);
        self.consecutive_failures.store(0, Ordering::SeqCst);
    }

    pub fn on_failure(&self, consensus_height: u64, error: &str) -> SyncAction {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        let last_executed = self.last_executed.load(Ordering::SeqCst);
        let divergence = consensus_height.saturating_sub(last_executed);

        error!(
            last_executed,
            consensus_height,
            divergence,
            consecutive_failures = failures,
            error,
            "Execution failed"
        );

        if divergence > self.config.max_divergence {
            return SyncAction::Halt {
                reason: format!(
                    "Divergence {} exceeds max {}. Last executed: {}, consensus: {}",
                    divergence, self.config.max_divergence, last_executed, consensus_height
                ),
            };
        }

        if failures > self.config.max_consecutive_failures {
            return SyncAction::Halt {
                reason: format!(
                    "Consecutive failures {} exceeds max {}",
                    failures, self.config.max_consecutive_failures
                ),
            };
        }

        SyncAction::Continue
    }

    pub fn last_executed(&self) -> u64 {
        self.last_executed.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_resets_failures() {
        let tracker = ExecutionSyncTracker::new(ExecutionSyncConfig::default());
        tracker.on_failure(5, "test");
        tracker.on_failure(6, "test");
        tracker.on_success(7);
        assert_eq!(tracker.consecutive_failures.load(Ordering::SeqCst), 0);
        assert_eq!(tracker.last_executed(), 7);
    }

    #[test]
    fn test_divergence_triggers_halt() {
        let config = ExecutionSyncConfig {
            max_divergence: 5,
            max_consecutive_failures: 100,
        };
        let tracker = ExecutionSyncTracker::new(config);
        tracker.on_success(10);
        let action = tracker.on_failure(16, "test");
        assert!(matches!(action, SyncAction::Halt { .. }));
    }

    #[test]
    fn test_consecutive_failures_triggers_halt() {
        let config = ExecutionSyncConfig {
            max_divergence: 100,
            max_consecutive_failures: 3,
        };
        let tracker = ExecutionSyncTracker::new(config);
        tracker.on_success(10);
        assert_eq!(tracker.on_failure(11, "e"), SyncAction::Continue);
        assert_eq!(tracker.on_failure(11, "e"), SyncAction::Continue);
        assert_eq!(tracker.on_failure(11, "e"), SyncAction::Continue);
        assert!(matches!(
            tracker.on_failure(11, "e"),
            SyncAction::Halt { .. }
        ));
    }
}
