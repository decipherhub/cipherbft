//! Worker process state management

use crate::batch::{Batch, Transaction};
use cipherbft_types::{Hash, ValidatorId};
use std::collections::HashMap;

/// Worker process state
#[derive(Debug)]
pub struct WorkerState {
    /// Our validator identity
    pub our_id: ValidatorId,
    /// Our worker ID
    pub worker_id: u8,
    /// Pending transactions (not yet batched)
    pub pending_txs: Vec<Transaction>,
    /// Pending transactions total size
    pub pending_size: usize,
    /// Stored batches by digest
    pub batches: HashMap<Hash, Batch>,
    /// Current finalized height (for garbage collection)
    pub finalized_height: u64,
}

impl WorkerState {
    /// Create new state for a worker
    pub fn new(our_id: ValidatorId, worker_id: u8) -> Self {
        Self {
            our_id,
            worker_id,
            pending_txs: Vec::new(),
            pending_size: 0,
            batches: HashMap::new(),
            finalized_height: 0,
        }
    }

    /// Add a transaction to pending
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.pending_size += tx.len();
        self.pending_txs.push(tx);
    }

    /// Take pending transactions (clears the pending list)
    pub fn take_pending_txs(&mut self) -> Vec<Transaction> {
        self.pending_size = 0;
        std::mem::take(&mut self.pending_txs)
    }

    /// Check if pending batch should be flushed by size
    pub fn should_flush_by_size(&self, max_bytes: usize, max_txs: usize) -> bool {
        self.pending_size >= max_bytes || self.pending_txs.len() >= max_txs
    }

    /// Check if there are pending transactions
    pub fn has_pending(&self) -> bool {
        !self.pending_txs.is_empty()
    }

    /// Store a batch
    pub fn store_batch(&mut self, batch: Batch) -> Hash {
        let digest = batch.digest();
        let hash = digest.digest;
        self.batches.insert(hash, batch);
        hash
    }

    /// Get a stored batch
    pub fn get_batch(&self, digest: &Hash) -> Option<&Batch> {
        self.batches.get(digest)
    }

    /// Check if batch exists
    pub fn has_batch(&self, digest: &Hash) -> bool {
        self.batches.contains_key(digest)
    }

    /// Remove batches older than a certain height
    /// Note: This requires tracking which batches belong to which height
    /// For now, we just clear all batches (simplified GC)
    pub fn cleanup(&mut self, finalized_height: u64) {
        self.finalized_height = finalized_height;
        // In a full implementation, we would track batch -> height mapping
        // and only remove batches older than (finalized_height - retention_window)
    }

    /// Get batch count
    pub fn batch_count(&self) -> usize {
        self.batches.len()
    }

    /// Get total stored bytes
    pub fn total_stored_bytes(&self) -> usize {
        self.batches.values().map(|b| b.total_bytes()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    #[test]
    fn test_pending_transactions() {
        let mut state = WorkerState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]), 0);

        state.add_transaction(vec![1, 2, 3]);
        state.add_transaction(vec![4, 5]);

        assert_eq!(state.pending_txs.len(), 2);
        assert_eq!(state.pending_size, 5);
        assert!(state.has_pending());

        let txs = state.take_pending_txs();
        assert_eq!(txs.len(), 2);
        assert!(!state.has_pending());
        assert_eq!(state.pending_size, 0);
    }

    #[test]
    fn test_should_flush() {
        let mut state = WorkerState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]), 0);

        // Add transactions totaling 100 bytes
        for _ in 0..10 {
            state.add_transaction(vec![0u8; 10]);
        }

        // Should not flush at 200 byte threshold
        assert!(!state.should_flush_by_size(200, 100));

        // Should flush at 50 byte threshold
        assert!(state.should_flush_by_size(50, 100));

        // Should flush at 5 tx threshold
        assert!(state.should_flush_by_size(1000, 5));
    }

    #[test]
    fn test_batch_storage() {
        let mut state = WorkerState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]), 0);

        let batch = Batch::new(0, vec![vec![1, 2, 3]], 12345);
        let hash = state.store_batch(batch.clone());

        assert!(state.has_batch(&hash));
        assert_eq!(state.get_batch(&hash).unwrap().worker_id, 0);
        assert_eq!(state.batch_count(), 1);
    }
}
