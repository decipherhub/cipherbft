//! Mempool configuration
//!
//! We primarily rely on Reth's `PoolConfig`, but expose a CipherBFT-friendly
//! wrapper so higher layers can express their preferences without depending
//! on Reth types directly.

use reth_transaction_pool::PoolConfig;
use serde::{Deserialize, Serialize};

/// Mempool configuration with CipherBFT-specific knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Maximum executable transactions to keep in the pending sub-pool.
    pub max_pending: usize,

    /// Maximum queued transactions per sender (maps to Reth's account slots).
    pub max_queued_per_sender: usize,

    /// Maximum nonce gap before the transaction is considered queued.
    pub max_nonce_gap: u64,

    /// Minimum gas price (in wei) we allow into the pool.
    pub min_gas_price: u128,

    /// Whether we allow Replace-By-Fee behaviour for the same nonce.
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

impl From<MempoolConfig> for PoolConfig {
    fn from(cfg: MempoolConfig) -> Self {
        let mut pool_cfg = PoolConfig::default();
        pool_cfg.pending_limit.max_txs = cfg.max_pending;
        pool_cfg.queued_limit.max_txs = cfg.max_pending;
        pool_cfg.max_account_slots = cfg.max_queued_per_sender;
        pool_cfg
    }
}

impl MempoolConfig {
    /// Convert borrowed configuration to the underlying Reth configuration.
    pub fn to_reth_config(&self) -> PoolConfig {
        let mut pool_cfg = PoolConfig::default();
        pool_cfg.pending_limit.max_txs = self.max_pending;
        pool_cfg.queued_limit.max_txs = self.max_pending;
        pool_cfg.max_account_slots = self.max_queued_per_sender;
        pool_cfg
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

    #[test]
    fn test_reth_conversion() {
        let cfg = MempoolConfig {
            max_pending: 5_000,
            max_queued_per_sender: 42,
            ..Default::default()
        };

        let reth_cfg = cfg.to_reth_config();
        assert_eq!(reth_cfg.pending_limit.max_txs, 5_000);
        assert_eq!(reth_cfg.queued_limit.max_txs, 5_000);
        assert_eq!(reth_cfg.max_account_slots, 42);
    }
}
