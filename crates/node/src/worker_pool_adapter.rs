//! Adapter for Workers to pull transactions from the mempool.
//!
//! This provides a simplified interface for Workers to get transactions
//! from the pool without needing to know the underlying pool implementation.

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::B256;
use reth_primitives::TransactionSigned;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use std::sync::Arc;
use tracing::info;

/// Adapter for Workers to get transactions from the pool.
///
/// Wraps a `TransactionPool` and provides worker-friendly methods
/// to retrieve and manage transactions for batch creation.
pub struct WorkerPoolAdapter<P: TransactionPool> {
    pool: Arc<P>,
    worker_id: u8,
}

impl<P: TransactionPool> WorkerPoolAdapter<P> {
    /// Create a new adapter.
    pub fn new(pool: Arc<P>, worker_id: u8) -> Self {
        Self { pool, worker_id }
    }

    /// Get the worker ID associated with this adapter.
    pub fn worker_id(&self) -> u8 {
        self.worker_id
    }
}

impl<P> WorkerPoolAdapter<P>
where
    P: TransactionPool,
    P::Transaction: PoolTransaction<Consensus = TransactionSigned>,
{
    /// Get best transactions for a batch, encoded as bytes.
    ///
    /// Transactions are returned in gas-price order (highest first),
    /// respecting nonce sequences per sender.
    ///
    /// # Arguments
    /// * `max_txs` - Maximum number of transactions to include
    /// * `gas_limit` - Maximum cumulative gas for the batch
    ///
    /// # Returns
    /// Vector of EIP-2718 encoded transactions
    pub fn get_transactions_for_batch(&self, max_txs: usize, gas_limit: u64) -> Vec<Vec<u8>> {
        let mut transactions = Vec::with_capacity(max_txs);
        let mut gas_used = 0u64;

        for tx in self.pool.best_transactions() {
            if transactions.len() >= max_txs {
                break;
            }

            let tx_gas = tx.gas_limit();
            if gas_used.saturating_add(tx_gas) > gas_limit {
                // Skip this transaction but continue looking for smaller ones
                continue;
            }

            gas_used += tx_gas;

            // Get the consensus transaction and encode it using EIP-2718 format
            let signed_tx = tx.transaction.clone_into_consensus().into_inner();
            let encoded = signed_tx.encoded_2718();
            transactions.push(encoded);
        }

        info!(
            worker_id = self.worker_id,
            tx_count = transactions.len(),
            gas_used,
            "Retrieved transactions for batch"
        );

        transactions
    }

    /// Get best transactions for a batch as signed transactions.
    ///
    /// This is useful when the caller needs to inspect transaction
    /// details before encoding.
    pub fn get_signed_transactions_for_batch(
        &self,
        max_txs: usize,
        gas_limit: u64,
    ) -> Vec<TransactionSigned> {
        let mut transactions = Vec::with_capacity(max_txs);
        let mut gas_used = 0u64;

        for tx in self.pool.best_transactions() {
            if transactions.len() >= max_txs {
                break;
            }

            let tx_gas = tx.gas_limit();
            if gas_used.saturating_add(tx_gas) > gas_limit {
                continue;
            }

            gas_used += tx_gas;
            let signed_tx = tx.transaction.clone_into_consensus().into_inner();
            transactions.push(signed_tx);
        }

        transactions
    }

    /// Mark transactions as included (removes from pool).
    ///
    /// Call this after a block containing these transactions has been finalized.
    pub fn mark_included(&self, tx_hashes: &[B256]) {
        if tx_hashes.is_empty() {
            return;
        }

        let removed = self.pool.remove_transactions(tx_hashes.to_vec());
        info!(
            worker_id = self.worker_id,
            requested = tx_hashes.len(),
            removed = removed.len(),
            "Removed included transactions from pool"
        );
    }

    /// Get current pool statistics.
    pub fn pool_size(&self) -> PoolSize {
        let size = self.pool.pool_size();
        PoolSize {
            pending: size.pending,
            queued: size.queued,
        }
    }
}

/// Pool size statistics.
#[derive(Debug, Clone, Copy)]
pub struct PoolSize {
    /// Number of pending (executable) transactions.
    pub pending: usize,
    /// Number of queued (future nonce) transactions.
    pub queued: usize,
}

impl PoolSize {
    /// Total number of transactions in the pool.
    pub fn total(&self) -> usize {
        self.pending + self.queued
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_size_total() {
        let size = PoolSize {
            pending: 10,
            queued: 5,
        };
        assert_eq!(size.total(), 15);
    }
}
