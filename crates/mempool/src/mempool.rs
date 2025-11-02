//! Transaction mempool implementation.
//!
//! Manages pending transactions with priority ordering and ABCI validation.

use crate::priority_queue::PriorityQueue;
use chrono::Utc;
use std::collections::HashMap;
use types::Hash;

/// Transaction mempool for managing pending transactions.
///
/// Stores transactions in a priority queue ordered by priority (gas price)
/// and provides efficient selection for block proposals.
#[derive(Debug)]
pub struct Mempool {
    /// Map of transaction hash to transaction bytes.
    transactions: HashMap<Hash, Vec<u8>>,
    /// Priority queue for transaction ordering.
    priority_queue: PriorityQueue,
    /// Current size in bytes.
    size_bytes: usize,
    /// Maximum size in bytes.
    max_size_bytes: usize,
    /// Cache for CheckTx results (hash -> is_valid).
    check_tx_cache: HashMap<Hash, bool>,
}

impl Mempool {
    /// Create a new mempool with default size limit (100 MB).
    pub fn new() -> Self {
        Self::with_max_size(100 * 1024 * 1024)
    }

    /// Create a new mempool with specified maximum size.
    pub fn with_max_size(max_size_bytes: usize) -> Self {
        Self {
            transactions: HashMap::new(),
            priority_queue: PriorityQueue::new(),
            size_bytes: 0,
            max_size_bytes,
            check_tx_cache: HashMap::new(),
        }
    }

    /// Add a transaction to the mempool.
    ///
    /// Returns `Ok(true)` if added, `Ok(false)` if duplicate, `Err` if mempool full.
    pub fn add_tx(&mut self, tx: Vec<u8>, priority: i64) -> Result<bool, MempoolError> {
        let tx_hash = Self::hash_tx(&tx);

        // Check if already exists
        if self.transactions.contains_key(&tx_hash) {
            return Ok(false);
        }

        let tx_size = tx.len();

        // Check if mempool would exceed size limit
        if self.size_bytes + tx_size > self.max_size_bytes {
            return Err(MempoolError::Full {
                current: self.size_bytes,
                max: self.max_size_bytes,
                attempted: tx_size,
            });
        }

        // Add to storage
        self.transactions.insert(tx_hash, tx);
        self.size_bytes += tx_size;

        // Add to priority queue
        self.priority_queue.insert(tx_hash, priority, Utc::now());

        Ok(true)
    }

    /// Select transactions for a block proposal up to max_bytes limit.
    ///
    /// Returns transactions in priority order (highest first).
    pub fn select_txs(&self, max_bytes: usize) -> Vec<Vec<u8>> {
        let mut selected = Vec::new();
        let mut total_bytes = 0;

        for entry in self.priority_queue.iter() {
            if let Some(tx) = self.transactions.get(&entry.tx_hash) {
                let tx_size = tx.len();
                if total_bytes + tx_size > max_bytes {
                    break;
                }
                selected.push(tx.clone());
                total_bytes += tx_size;
            }
        }

        selected
    }

    /// Remove transactions from the mempool.
    ///
    /// Typically called after transactions are included in a block.
    pub fn remove_txs(&mut self, tx_hashes: &[Hash]) -> usize {
        let mut removed_count = 0;

        for tx_hash in tx_hashes {
            if let Some(tx) = self.transactions.remove(tx_hash) {
                self.size_bytes -= tx.len();
                self.priority_queue.remove(tx_hash);
                self.check_tx_cache.remove(tx_hash);
                removed_count += 1;
            }
        }

        removed_count
    }

    /// Get the current number of transactions in the mempool.
    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    /// Get the current size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.size_bytes
    }

    /// Check if a transaction exists in the mempool.
    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    /// Get a transaction by hash.
    pub fn get_tx(&self, tx_hash: &Hash) -> Option<&Vec<u8>> {
        self.transactions.get(tx_hash)
    }

    /// Clear all transactions from the mempool.
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.priority_queue.clear();
        self.check_tx_cache.clear();
        self.size_bytes = 0;
    }

    /// Cache a CheckTx result.
    pub fn cache_check_tx(&mut self, tx_hash: Hash, is_valid: bool) {
        self.check_tx_cache.insert(tx_hash, is_valid);
    }

    /// Get a cached CheckTx result.
    pub fn get_cached_check_tx(&self, tx_hash: &Hash) -> Option<bool> {
        self.check_tx_cache.get(tx_hash).copied()
    }

    /// Compute hash of transaction bytes.
    fn hash_tx(tx: &[u8]) -> Hash {
        use crypto::hash;
        Hash::from(hash(tx))
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

/// Mempool error types.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    /// Mempool is full.
    #[error("Mempool full: {current}/{max} bytes, attempted to add {attempted} bytes")]
    Full {
        /// Current size.
        current: usize,
        /// Maximum size.
        max: usize,
        /// Attempted addition size.
        attempted: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mempool_creation() {
        let mempool = Mempool::new();
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.size_bytes(), 0);
    }

    #[test]
    fn test_add_transaction() {
        let mut mempool = Mempool::new();

        let tx = vec![1, 2, 3, 4, 5];
        let result = mempool.add_tx(tx.clone(), 10);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.size_bytes(), 5);
    }

    #[test]
    fn test_duplicate_transaction() {
        let mut mempool = Mempool::new();

        let tx = vec![1, 2, 3];
        mempool.add_tx(tx.clone(), 10).unwrap();

        // Try adding same transaction again
        let result = mempool.add_tx(tx, 20);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
        assert_eq!(mempool.size(), 1);
    }

    #[test]
    fn test_mempool_full() {
        let mut mempool = Mempool::with_max_size(10);

        let tx1 = vec![1, 2, 3, 4, 5]; // 5 bytes
        let tx2 = vec![6, 7, 8, 9, 10]; // 5 bytes
        let tx3 = vec![11, 12]; // 2 bytes - would exceed limit

        assert!(mempool.add_tx(tx1, 10).is_ok());
        assert!(mempool.add_tx(tx2, 20).is_ok());

        let result = mempool.add_tx(tx3, 30);
        assert!(result.is_err());
        assert!(matches!(result, Err(MempoolError::Full { .. })));
    }

    #[test]
    fn test_select_txs() {
        let mut mempool = Mempool::new();

        let tx1 = vec![1; 100]; // 100 bytes, priority 10
        let tx2 = vec![2; 100]; // 100 bytes, priority 30
        let tx3 = vec![3; 100]; // 100 bytes, priority 20

        mempool.add_tx(tx1, 10).unwrap();
        mempool.add_tx(tx2.clone(), 30).unwrap();
        mempool.add_tx(tx3.clone(), 20).unwrap();

        // Select up to 250 bytes (should get all 3 in priority order)
        let selected = mempool.select_txs(250);
        assert_eq!(selected.len(), 2); // Only 200 bytes fit

        // Highest priority (30) should be first
        assert_eq!(selected[0], tx2);
        // Second highest (20) should be second
        assert_eq!(selected[1], tx3);
    }

    #[test]
    fn test_select_txs_byte_limit() {
        let mut mempool = Mempool::new();

        let tx1 = vec![1; 50];
        let tx2 = vec![2; 50];
        let tx3 = vec![3; 50];

        mempool.add_tx(tx1.clone(), 30).unwrap();
        mempool.add_tx(tx2.clone(), 20).unwrap();
        mempool.add_tx(tx3, 10).unwrap();

        // Select only 80 bytes (should get only first tx)
        let selected = mempool.select_txs(80);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], tx1);
    }

    #[test]
    fn test_remove_txs() {
        let mut mempool = Mempool::new();

        let tx1 = vec![1, 2, 3];
        let tx2 = vec![4, 5, 6];

        mempool.add_tx(tx1.clone(), 10).unwrap();
        mempool.add_tx(tx2.clone(), 20).unwrap();

        let tx1_hash = Mempool::hash_tx(&tx1);
        let tx2_hash = Mempool::hash_tx(&tx2);

        assert_eq!(mempool.size(), 2);

        let removed = mempool.remove_txs(&[tx1_hash]);
        assert_eq!(removed, 1);
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.size_bytes(), 3);
        assert!(!mempool.contains(&tx1_hash));
        assert!(mempool.contains(&tx2_hash));
    }

    #[test]
    fn test_contains() {
        let mut mempool = Mempool::new();

        let tx = vec![1, 2, 3];
        let tx_hash = Mempool::hash_tx(&tx);

        assert!(!mempool.contains(&tx_hash));

        mempool.add_tx(tx, 10).unwrap();
        assert!(mempool.contains(&tx_hash));
    }

    #[test]
    fn test_get_tx() {
        let mut mempool = Mempool::new();

        let tx = vec![1, 2, 3, 4, 5];
        let tx_hash = Mempool::hash_tx(&tx);

        assert!(mempool.get_tx(&tx_hash).is_none());

        mempool.add_tx(tx.clone(), 10).unwrap();
        assert_eq!(mempool.get_tx(&tx_hash), Some(&tx));
    }

    #[test]
    fn test_clear() {
        let mut mempool = Mempool::new();

        mempool.add_tx(vec![1, 2, 3], 10).unwrap();
        mempool.add_tx(vec![4, 5, 6], 20).unwrap();

        assert_eq!(mempool.size(), 2);

        mempool.clear();

        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.size_bytes(), 0);
    }

    #[test]
    fn test_check_tx_cache() {
        let mut mempool = Mempool::new();

        let tx = vec![1, 2, 3];
        let tx_hash = Mempool::hash_tx(&tx);

        assert!(mempool.get_cached_check_tx(&tx_hash).is_none());

        mempool.cache_check_tx(tx_hash, true);
        assert_eq!(mempool.get_cached_check_tx(&tx_hash), Some(true));

        mempool.cache_check_tx(tx_hash, false);
        assert_eq!(mempool.get_cached_check_tx(&tx_hash), Some(false));
    }
}
