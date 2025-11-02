//! Timeout management for Autobahn BFT consensus.
//!
//! Implements timeout scheduling with exponential backoff for round progression.

use std::time::Duration;
use types::Round;

/// Timeout configuration for consensus steps.
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Base timeout for propose step (milliseconds).
    pub timeout_propose: u64,
    /// Base timeout for prepare step (milliseconds).
    pub timeout_prepare: u64,
    /// Base timeout for commit step (milliseconds).
    pub timeout_commit: u64,
    /// Exponential backoff multiplier (e.g., 1.5 means 50% increase per round).
    pub timeout_delta: f64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            timeout_propose: 3000,  // 3 seconds
            timeout_prepare: 1000,  // 1 second
            timeout_commit: 1000,   // 1 second
            timeout_delta: 0.5,     // 50% increase per round
        }
    }
}

/// Consensus step for which timeout is calculated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutStep {
    /// Propose step timeout.
    Propose,
    /// Prepare step timeout.
    Prepare,
    /// Commit step timeout.
    Commit,
}

/// Timeout manager with exponential backoff.
#[derive(Debug, Clone)]
pub struct TimeoutManager {
    config: TimeoutConfig,
}

impl TimeoutManager {
    /// Create a new timeout manager.
    pub fn new(config: TimeoutConfig) -> Self {
        Self { config }
    }

    /// Create timeout manager with default config.
    pub fn with_defaults() -> Self {
        Self::new(TimeoutConfig::default())
    }

    /// Calculate timeout duration for a specific step and round.
    ///
    /// Uses exponential backoff: base_timeout * (1 + delta)^round
    pub fn timeout_duration(&self, step: TimeoutStep, round: Round) -> Duration {
        let base_timeout = match step {
            TimeoutStep::Propose => self.config.timeout_propose,
            TimeoutStep::Prepare => self.config.timeout_prepare,
            TimeoutStep::Commit => self.config.timeout_commit,
        };

        let round_value = round.value() as f64;
        let multiplier = (1.0 + self.config.timeout_delta).powf(round_value);
        let timeout_ms = (base_timeout as f64 * multiplier) as u64;

        Duration::from_millis(timeout_ms)
    }

    /// Get propose timeout for a round.
    pub fn timeout_propose(&self, round: Round) -> Duration {
        self.timeout_duration(TimeoutStep::Propose, round)
    }

    /// Get prepare timeout for a round.
    pub fn timeout_prepare(&self, round: Round) -> Duration {
        self.timeout_duration(TimeoutStep::Prepare, round)
    }

    /// Get commit timeout for a round.
    pub fn timeout_commit(&self, round: Round) -> Duration {
        self.timeout_duration(TimeoutStep::Commit, round)
    }
}

/// Timeout scheduler for triggering view changes.
#[derive(Debug)]
pub struct TimeoutScheduler {
    manager: TimeoutManager,
    current_round: Round,
}

impl TimeoutScheduler {
    /// Create a new timeout scheduler.
    pub fn new(manager: TimeoutManager) -> Self {
        Self {
            manager,
            current_round: Round::default(),
        }
    }

    /// Update the current round.
    pub fn set_round(&mut self, round: Round) {
        self.current_round = round;
    }

    /// Get current round.
    pub fn current_round(&self) -> Round {
        self.current_round
    }

    /// Trigger a view change to the next round.
    ///
    /// Returns the new round number.
    pub fn trigger_view_change(&mut self) -> Round {
        let next_round = Round::new(self.current_round.value() + 1);
        self.current_round = next_round;
        next_round
    }

    /// Schedule a propose timeout.
    ///
    /// Returns the timeout duration for the current round.
    pub fn schedule_propose(&self) -> Duration {
        self.manager.timeout_propose(self.current_round)
    }

    /// Schedule a prepare timeout.
    ///
    /// Returns the timeout duration for the current round.
    pub fn schedule_prepare(&self) -> Duration {
        self.manager.timeout_prepare(self.current_round)
    }

    /// Schedule a commit timeout.
    ///
    /// Returns the timeout duration for the current round.
    pub fn schedule_commit(&self) -> Duration {
        self.manager.timeout_commit(self.current_round)
    }

    /// Get all timeouts for the current round.
    pub fn all_timeouts(&self) -> (Duration, Duration, Duration) {
        (
            self.schedule_propose(),
            self.schedule_prepare(),
            self.schedule_commit(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_config_default() {
        let config = TimeoutConfig::default();
        assert_eq!(config.timeout_propose, 3000);
        assert_eq!(config.timeout_prepare, 1000);
        assert_eq!(config.timeout_commit, 1000);
        assert_eq!(config.timeout_delta, 0.5);
    }

    #[test]
    fn test_timeout_manager_creation() {
        let manager = TimeoutManager::with_defaults();
        let duration = manager.timeout_propose(Round::new(0));
        assert_eq!(duration, Duration::from_millis(3000));
    }

    #[test]
    fn test_timeout_exponential_backoff() {
        let manager = TimeoutManager::with_defaults();

        // Round 0: base timeout
        let timeout0 = manager.timeout_propose(Round::new(0));
        assert_eq!(timeout0, Duration::from_millis(3000));

        // Round 1: 1.5x base timeout
        let timeout1 = manager.timeout_propose(Round::new(1));
        assert_eq!(timeout1, Duration::from_millis(4500));

        // Round 2: 2.25x base timeout
        let timeout2 = manager.timeout_propose(Round::new(2));
        assert_eq!(timeout2, Duration::from_millis(6750));

        // Round 3: 3.375x base timeout
        let timeout3 = manager.timeout_propose(Round::new(3));
        assert_eq!(timeout3, Duration::from_millis(10125));
    }

    #[test]
    fn test_different_step_timeouts() {
        let manager = TimeoutManager::with_defaults();
        let round = Round::new(0);

        let propose = manager.timeout_propose(round);
        let prepare = manager.timeout_prepare(round);
        let commit = manager.timeout_commit(round);

        assert_eq!(propose, Duration::from_millis(3000));
        assert_eq!(prepare, Duration::from_millis(1000));
        assert_eq!(commit, Duration::from_millis(1000));
    }

    #[test]
    fn test_custom_timeout_config() {
        let config = TimeoutConfig {
            timeout_propose: 5000,
            timeout_prepare: 2000,
            timeout_commit: 2000,
            timeout_delta: 1.0, // Double each round
        };

        let manager = TimeoutManager::new(config);

        // Round 0
        assert_eq!(
            manager.timeout_propose(Round::new(0)),
            Duration::from_millis(5000)
        );

        // Round 1: 2x
        assert_eq!(
            manager.timeout_propose(Round::new(1)),
            Duration::from_millis(10000)
        );

        // Round 2: 4x
        assert_eq!(
            manager.timeout_propose(Round::new(2)),
            Duration::from_millis(20000)
        );
    }

    #[test]
    fn test_timeout_scheduler_creation() {
        let manager = TimeoutManager::with_defaults();
        let scheduler = TimeoutScheduler::new(manager);

        assert_eq!(scheduler.current_round(), Round::new(0));
    }

    #[test]
    fn test_timeout_scheduler_set_round() {
        let manager = TimeoutManager::with_defaults();
        let mut scheduler = TimeoutScheduler::new(manager);

        scheduler.set_round(Round::new(5));
        assert_eq!(scheduler.current_round(), Round::new(5));
    }

    #[test]
    fn test_view_change_progression() {
        let manager = TimeoutManager::with_defaults();
        let mut scheduler = TimeoutScheduler::new(manager);

        assert_eq!(scheduler.current_round(), Round::new(0));

        let round1 = scheduler.trigger_view_change();
        assert_eq!(round1, Round::new(1));
        assert_eq!(scheduler.current_round(), Round::new(1));

        let round2 = scheduler.trigger_view_change();
        assert_eq!(round2, Round::new(2));
        assert_eq!(scheduler.current_round(), Round::new(2));
    }

    #[test]
    fn test_scheduler_timeouts() {
        let manager = TimeoutManager::with_defaults();
        let mut scheduler = TimeoutScheduler::new(manager);

        // Round 0
        assert_eq!(
            scheduler.schedule_propose(),
            Duration::from_millis(3000)
        );
        assert_eq!(
            scheduler.schedule_prepare(),
            Duration::from_millis(1000)
        );
        assert_eq!(
            scheduler.schedule_commit(),
            Duration::from_millis(1000)
        );

        // Advance to round 1
        scheduler.trigger_view_change();

        assert_eq!(
            scheduler.schedule_propose(),
            Duration::from_millis(4500)
        );
    }

    #[test]
    fn test_all_timeouts() {
        let manager = TimeoutManager::with_defaults();
        let scheduler = TimeoutScheduler::new(manager);

        let (propose, prepare, commit) = scheduler.all_timeouts();

        assert_eq!(propose, Duration::from_millis(3000));
        assert_eq!(prepare, Duration::from_millis(1000));
        assert_eq!(commit, Duration::from_millis(1000));
    }

    #[test]
    fn test_timeout_growth_rate() {
        let manager = TimeoutManager::with_defaults();

        // Verify exponential growth pattern
        let round0 = manager.timeout_propose(Round::new(0)).as_millis();
        let round1 = manager.timeout_propose(Round::new(1)).as_millis();
        let round2 = manager.timeout_propose(Round::new(2)).as_millis();

        // Each round should be 1.5x the previous
        let ratio1 = round1 as f64 / round0 as f64;
        let ratio2 = round2 as f64 / round1 as f64;

        assert!((ratio1 - 1.5).abs() < 0.01);
        assert!((ratio2 - 1.5).abs() < 0.01);
    }
}
