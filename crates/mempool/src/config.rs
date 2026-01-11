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
    pub max_queued_per_account: usize,

    /// Maximum nonce gap before the transaction is considered queued.
    pub max_nonce_gap: u64,

    /// Minimum gas price (in wei) we allow into the pool.
    pub min_gas_price: u128,

    /// Default price bump (in %) required to replace a transaction.
    pub default_price_bump: u128,

    /// Price bump (in %) required to replace a blob transaction.
    pub replace_blob_tx_price_bump: u128,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pending: 10_000,
            max_queued_per_account: 100,
            max_nonce_gap: 16,
            min_gas_price: 1_000_000_000, // 1 gwei
            default_price_bump: 10,
            replace_blob_tx_price_bump: 100,
        }
    }
}

impl From<MempoolConfig> for PoolConfig {
    fn from(cfg: MempoolConfig) -> Self {
        let mut pool_cfg = PoolConfig::default();
        pool_cfg.pending_limit.max_txs = cfg.max_pending;
        pool_cfg.queued_limit.max_txs = cfg.max_pending;
        pool_cfg.max_account_slots = cfg.max_queued_per_account;
        pool_cfg.price_bumps.default_price_bump = cfg.default_price_bump;
        pool_cfg.price_bumps.replace_blob_tx_price_bump = cfg.replace_blob_tx_price_bump;

        // TODO: map min_gas_price and max_nonce_gap once upstream hooks are wired.
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
        assert_eq!(cfg.max_queued_per_account, 100);
        assert_eq!(cfg.max_nonce_gap, 16);
        assert_eq!(cfg.min_gas_price, 1_000_000_000);
        assert_eq!(cfg.default_price_bump, 10);
        assert_eq!(cfg.replace_blob_tx_price_bump, 100);
    }

    #[test]
    fn test_reth_conversion() {
        let cfg = MempoolConfig {
            max_pending: 5_000,
            max_queued_per_account: 42,
            default_price_bump: 25,
            replace_blob_tx_price_bump: 150,
            ..Default::default()
        };

        let reth_cfg: PoolConfig = cfg.into();
        assert_eq!(reth_cfg.pending_limit.max_txs, 5_000);
        assert_eq!(reth_cfg.queued_limit.max_txs, 5_000);
        assert_eq!(reth_cfg.max_account_slots, 42);
        assert_eq!(reth_cfg.price_bumps.default_price_bump, 25);
        assert_eq!(reth_cfg.price_bumps.replace_blob_tx_price_bump, 150);
    }
}
