//! CipherBFT mempool wrapper over Reth's TransactionPool
//!
//! MP-1 범위: 데이터 구조 정의만 유지. 실제 로직은 후속 단계에서 채운다.

use crate::config::MempoolConfig;
use reth_transaction_pool::{PoolConfig, TransactionPool};

/// Main mempool wrapper over Reth's TransactionPool
///
/// Thin adapter that delegates all TX storage, validation, and state management to Reth.
/// Provides BFT-specific constraints (nonce gaps) and batch selection.
pub struct CipherBftPool<P: TransactionPool> {
    /// Underlying Reth pool - all functionality delegated here
    pool: P,
    /// BFT-specific config
    config: MempoolConfig,
}

impl<P: TransactionPool> CipherBftPool<P> {
    /// Create new mempool wrapper
    pub fn new(pool: P, config: MempoolConfig) -> Self {
        Self { pool, config }
    }

    /// Get the underlying Reth pool
    pub fn pool(&self) -> &P {
        &self.pool
    }

    /// Get mutable reference to underlying Reth pool
    pub fn pool_mut(&mut self) -> &mut P {
        &mut self.pool
    }

    /// Get BFT config
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Convert to the underlying Reth pool configuration.
    pub fn reth_config(&self) -> PoolConfig {
        self.config.to_reth_config()
    }
}

