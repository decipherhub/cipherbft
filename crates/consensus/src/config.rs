use std::time::Duration;

/// Basic consensus configuration shared with the Malachite context.
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    /// Chain identifier used for domain separation.
    pub chain_id: String,
    /// Timeout for proposal creation/broadcast.
    pub propose_timeout: Duration,
    /// Timeout for prevote step.
    pub prevote_timeout: Duration,
    /// Timeout for precommit step.
    pub precommit_timeout: Duration,
}

impl ConsensusConfig {
    /// Create a new config with sensible defaults.
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            propose_timeout: Duration::from_secs(1),
            prevote_timeout: Duration::from_secs(1),
            precommit_timeout: Duration::from_secs(1),
        }
    }

    /// Set proposal timeout.
    pub fn with_propose_timeout(mut self, duration: Duration) -> Self {
        self.propose_timeout = duration;
        self
    }

    /// Set prevote timeout.
    pub fn with_prevote_timeout(mut self, duration: Duration) -> Self {
        self.prevote_timeout = duration;
        self
    }

    /// Set precommit timeout.
    pub fn with_precommit_timeout(mut self, duration: Duration) -> Self {
        self.precommit_timeout = duration;
        self
    }

    /// Chain ID accessor.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
}
