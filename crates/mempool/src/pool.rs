//! CipherBFT mempool over Reth's TransactionPool

use crate::{account::AccountState, config::MempoolConfig, transaction::TransactionInfo};
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

    /// Sender-address to transaction hashes index
    sender_index: HashMap<Address, Vec<B256>>,
}

impl<P: TransactionPool> CipherBftPool<P> {
    /// Create new mempool
    pub fn new(pool: P, config: MempoolConfig) -> Self {
        Self {
            pool,
            config,
            accounts: HashMap::new(),
            sender_index: HashMap::new(),
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

    /// Get all transaction hashes for a sender (if any)
    pub fn sender_transactions(&self, address: &Address) -> Option<&Vec<B256>> {
        self.sender_index.get(address)
    }

    /// Index a transaction by its sender and hash. No-op if already indexed.
    pub fn index_transaction(&mut self, tx: &TransactionInfo) {
        let entry = self.sender_index.entry(tx.sender).or_default();
        if !entry.contains(&tx.hash) {
            entry.push(tx.hash);
        }
    }

    /// Remove a transaction hash from the sender index. Returns true if removed.
    pub fn remove_transaction_from_index(&mut self, sender: &Address, hash: &B256) -> bool {
        if let Some(list) = self.sender_index.get_mut(sender) {
            let original_len = list.len();
            list.retain(|h| h != hash);
            if list.is_empty() {
                self.sender_index.remove(sender);
            }
            return list.len() != original_len;
        }
        false
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
