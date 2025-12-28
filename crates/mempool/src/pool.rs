//! CipherBFT mempool over Reth's TransactionPool

use crate::{config::MempoolConfig, error::MempoolError, account::AccountState};
use reth_primitives::{Address, B256};
use reth_transaction_pool::TransactionPool;
use std::collections::HashMap;

/// Main mempool wrapper over Reth's TransactionPool
pub struct CipherBftPool<P: TransactionPool> {
    /// Underlying Reth pool
    pool: P,

    /// Configuration
    config: MempoolConfig,

    /// Per-account states
    accounts: HashMap<Address, AccountState>,
}

impl<P: TransactionPool> CipherBftPool<P> {
    /// Create new mempool
    pub fn new(pool: P, config: MempoolConfig) -> Self {
        Self {
            pool,
            config,
            accounts: HashMap::new(),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Get or create account state
    pub fn get_or_create_account(&mut self, address: Address) -> &mut AccountState {
        self.accounts
            .entry(address)
            .or_insert_with(|| AccountState::new(0))
    }

    /// Get account state
    pub fn get_account(&self, address: Address) -> Option<&AccountState> {
        self.accounts.get(&address)
    }

    /// Pool size information
    pub fn size(&self) -> PoolSize {
        let reth_size = self.pool.pool_size();
        PoolSize {
            pending: reth_size.pending,
            queued: reth_size.queued,
        }
    }

    /// Number of unique senders
    pub fn num_senders(&self) -> usize {
        self.accounts.len()
    }
}

/// Pool size information
#[derive(Clone, Copy, Debug)]
pub struct PoolSize {
    pub pending: usize,
    pub queued: usize,
}

impl PoolSize {
    pub fn total(&self) -> usize {
        self.pending + self.queued
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_size() {
        let size = PoolSize {
            pending: 1000,
            queued: 500,
        };
        assert_eq!(size.total(), 1500);
    }
}
