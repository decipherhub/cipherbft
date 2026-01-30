//! Worker process configuration

use cipherbft_types::ValidatorId;
use std::time::Duration;

/// Worker process configuration
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Our validator identity
    pub validator_id: ValidatorId,
    /// Worker ID (0-7)
    pub worker_id: u8,
    /// Maximum batch size in bytes (default: 1MB)
    pub max_batch_bytes: usize,
    /// Maximum batch transaction count (default: 1000)
    pub max_batch_txs: usize,
    /// Time-based flush interval (default: 100ms)
    pub flush_interval: Duration,
}

impl WorkerConfig {
    /// Create a new configuration with defaults
    ///
    /// Default batch thresholds are tuned for responsive transaction processing:
    /// - `max_batch_txs`: 100 transactions triggers immediate batch flush
    /// - `flush_interval`: 50ms ensures batches don't wait too long
    pub fn new(validator_id: ValidatorId, worker_id: u8) -> Self {
        Self {
            validator_id,
            worker_id,
            max_batch_bytes: 1024 * 1024, // 1MB
            max_batch_txs: 100, // Flush after 100 txs for responsive batching
            flush_interval: Duration::from_millis(50), // Faster time-based flush
        }
    }

    /// Set maximum batch size in bytes
    pub fn with_max_batch_bytes(mut self, bytes: usize) -> Self {
        self.max_batch_bytes = bytes;
        self
    }

    /// Set maximum batch transaction count
    pub fn with_max_batch_txs(mut self, count: usize) -> Self {
        self.max_batch_txs = count;
        self
    }

    /// Set flush interval
    pub fn with_flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }
}
