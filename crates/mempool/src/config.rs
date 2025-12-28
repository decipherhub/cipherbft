//! Mempool configuration

use serde::{Deserialize, Serialize};

/// Mempool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Maximum pending (executable) transactions
    pub max_pending: usize,

    /// Maximum queued transactions per sender
    pub max_queued_per_sender: usize,

    /// Maximum nonce gap before transaction is queued
    pub max_nonce_gap: u64,

    /// Minimum gas price (in wei)
    pub min_gas_price: u128,

    /// Enable RBF (Replace-By-Fee)
    pub enable_rbf: bool,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pending: 10_000,
            max_queued_per_sender: 100,
            max_nonce_gap: 16,
            min_gas_price: 1_000_000_000, // 1 gwei
            enable_rbf: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = MempoolConfig::default();
        assert_eq!(cfg.max_pending, 10_000);
        assert_eq!(cfg.max_queued_per_sender, 100);
        assert_eq!(cfg.max_nonce_gap, 16);
        assert_eq!(cfg.min_gas_price, 1_000_000_000);
        assert!(cfg.enable_rbf);
    }
}
