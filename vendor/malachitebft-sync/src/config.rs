use std::time::Duration;

use crate::scoring::Strategy;

const DEFAULT_PARALLEL_REQUESTS: u64 = 5;
const DEFAULT_TIP_FIRST_BUFFER: u64 = 100;

#[derive(Copy, Clone, Debug)]
pub struct Config {
    pub enabled: bool,
    pub request_timeout: Duration,
    pub max_request_size: usize,
    pub max_response_size: usize,
    pub parallel_requests: u64,
    pub scoring_strategy: Strategy,
    pub inactive_threshold: Option<Duration>,
    /// When enabled, sync starts from near the network tip instead of genesis.
    /// This allows nodes to quickly join consensus without syncing full history.
    pub tip_first_sync: bool,
    /// Number of blocks before tip to start syncing from when tip_first_sync is enabled.
    /// Default: 100 blocks. This ensures enough recent history for consensus participation.
    pub tip_first_buffer: u64,
}

impl Config {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }

    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    pub fn with_max_request_size(mut self, max_request_size: usize) -> Self {
        self.max_request_size = max_request_size;
        self
    }

    pub fn with_max_response_size(mut self, max_response_size: usize) -> Self {
        self.max_response_size = max_response_size;
        self
    }

    pub fn with_parallel_requests(mut self, parallel_requests: u64) -> Self {
        self.parallel_requests = parallel_requests;
        self
    }

    pub fn with_scoring_strategy(mut self, scoring_strategy: Strategy) -> Self {
        self.scoring_strategy = scoring_strategy;
        self
    }

    pub fn with_inactive_threshold(mut self, inactive_threshold: Option<Duration>) -> Self {
        self.inactive_threshold = inactive_threshold;
        self
    }

    /// Enable tip-first sync mode where sync starts from near the network tip
    /// instead of genesis. This allows faster consensus participation.
    pub fn with_tip_first_sync(mut self, enabled: bool) -> Self {
        self.tip_first_sync = enabled;
        self
    }

    /// Set the number of blocks before tip to start syncing from.
    /// Only used when tip_first_sync is enabled.
    pub fn with_tip_first_buffer(mut self, buffer: u64) -> Self {
        self.tip_first_buffer = buffer;
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            request_timeout: Duration::from_secs(10),
            max_request_size: 1024 * 1024,        // 1 MiB
            max_response_size: 512 * 1024 * 1024, // 512 MiB
            parallel_requests: DEFAULT_PARALLEL_REQUESTS,
            scoring_strategy: Strategy::default(),
            inactive_threshold: None,
            tip_first_sync: false, // Disabled by default for safety
            tip_first_buffer: DEFAULT_TIP_FIRST_BUFFER,
        }
    }
}
