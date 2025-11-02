//! Priority queue for transaction ordering.
//!
//! Orders transactions by priority (desc) and timestamp (asc).

use chrono::{DateTime, Utc};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use types::Hash;

/// Priority queue entry for a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityEntry {
    /// Transaction hash.
    pub tx_hash: Hash,
    /// Transaction priority (higher is better).
    pub priority: i64,
    /// Timestamp when transaction was added.
    pub timestamp: DateTime<Utc>,
}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // First compare by priority (descending - higher priority first)
        match other.priority.cmp(&self.priority) {
            Ordering::Equal => {
                // Then by timestamp (ascending - older first)
                match self.timestamp.cmp(&other.timestamp) {
                    Ordering::Equal => {
                        // Finally by hash for deterministic ordering
                        self.tx_hash.as_bytes().cmp(other.tx_hash.as_bytes())
                    }
                    ord => ord,
                }
            }
            ord => ord,
        }
    }
}

/// Priority queue for transaction ordering.
///
/// Uses a BTreeSet for O(log n) insertion/removal and O(1) iteration in priority order.
/// Uses a HashMap to track tx_hash uniqueness.
#[derive(Debug, Clone)]
pub struct PriorityQueue {
    entries: BTreeSet<PriorityEntry>,
    hash_to_entry: HashMap<Hash, PriorityEntry>,
}

impl PriorityQueue {
    /// Create a new empty priority queue.
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            hash_to_entry: HashMap::new(),
        }
    }

    /// Insert a transaction into the queue.
    ///
    /// Returns true if inserted, false if already exists.
    pub fn insert(&mut self, tx_hash: Hash, priority: i64, timestamp: DateTime<Utc>) -> bool {
        // Check if already exists
        if self.hash_to_entry.contains_key(&tx_hash) {
            return false;
        }

        let entry = PriorityEntry {
            tx_hash,
            priority,
            timestamp,
        };

        self.entries.insert(entry.clone());
        self.hash_to_entry.insert(tx_hash, entry);
        true
    }

    /// Pop the highest priority transaction.
    ///
    /// Returns None if queue is empty.
    pub fn pop_highest(&mut self) -> Option<Hash> {
        // BTreeSet iteration is in sorted order (lowest to highest)
        // We sorted in reverse, so first() gives highest priority
        if let Some(entry) = self.entries.iter().next().cloned() {
            self.entries.remove(&entry);
            self.hash_to_entry.remove(&entry.tx_hash);
            Some(entry.tx_hash)
        } else {
            None
        }
    }

    /// Remove a transaction from the queue.
    ///
    /// Returns true if the transaction was removed, false if not found.
    pub fn remove(&mut self, tx_hash: &Hash) -> bool {
        if let Some(entry) = self.hash_to_entry.remove(tx_hash) {
            self.entries.remove(&entry);
            true
        } else {
            false
        }
    }

    /// Check if queue contains a transaction.
    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.hash_to_entry.contains_key(tx_hash)
    }

    /// Get the number of transactions in the queue.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an iterator over transactions in priority order.
    pub fn iter(&self) -> impl Iterator<Item = &PriorityEntry> {
        self.entries.iter()
    }

    /// Clear all transactions from the queue.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.hash_to_entry.clear();
    }
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_queue_creation() {
        let queue = PriorityQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_insert_and_pop() {
        let mut queue = PriorityQueue::new();

        let tx1 = Hash::new([1; 32]);
        let tx2 = Hash::new([2; 32]);

        assert!(queue.insert(tx1, 10, Utc::now()));
        assert!(queue.insert(tx2, 20, Utc::now()));

        assert_eq!(queue.len(), 2);

        // tx2 has higher priority, should be popped first
        assert_eq!(queue.pop_highest(), Some(tx2));
        assert_eq!(queue.pop_highest(), Some(tx1));
        assert_eq!(queue.pop_highest(), None);
    }

    #[test]
    fn test_priority_ordering() {
        let mut queue = PriorityQueue::new();
        let now = Utc::now();

        let tx1 = Hash::new([1; 32]);
        let tx2 = Hash::new([2; 32]);
        let tx3 = Hash::new([3; 32]);

        // Insert in reverse priority order
        queue.insert(tx1, 10, now);
        queue.insert(tx2, 30, now);
        queue.insert(tx3, 20, now);

        // Should pop in priority order (30, 20, 10)
        assert_eq!(queue.pop_highest(), Some(tx2));
        assert_eq!(queue.pop_highest(), Some(tx3));
        assert_eq!(queue.pop_highest(), Some(tx1));
    }

    #[test]
    fn test_timestamp_ordering_same_priority() {
        let mut queue = PriorityQueue::new();

        let tx1 = Hash::new([1; 32]);
        let tx2 = Hash::new([2; 32]);

        let time1 = Utc::now();
        let time2 = time1 + chrono::Duration::milliseconds(100);

        // Both have same priority, but different timestamps
        queue.insert(tx2, 10, time2);
        queue.insert(tx1, 10, time1);

        // Should pop older transaction first
        assert_eq!(queue.pop_highest(), Some(tx1));
        assert_eq!(queue.pop_highest(), Some(tx2));
    }

    #[test]
    fn test_remove() {
        let mut queue = PriorityQueue::new();

        let tx1 = Hash::new([1; 32]);
        let tx2 = Hash::new([2; 32]);
        let tx3 = Hash::new([3; 32]);

        queue.insert(tx1, 10, Utc::now());
        queue.insert(tx2, 20, Utc::now());
        queue.insert(tx3, 30, Utc::now());

        assert_eq!(queue.len(), 3);

        // Remove middle priority transaction
        assert!(queue.remove(&tx2));
        assert_eq!(queue.len(), 2);
        assert!(!queue.contains(&tx2));

        // Try removing again
        assert!(!queue.remove(&tx2));

        // Remaining transactions should be in order
        assert_eq!(queue.pop_highest(), Some(tx3));
        assert_eq!(queue.pop_highest(), Some(tx1));
    }

    #[test]
    fn test_contains() {
        let mut queue = PriorityQueue::new();

        let tx1 = Hash::new([1; 32]);
        let tx2 = Hash::new([2; 32]);

        queue.insert(tx1, 10, Utc::now());

        assert!(queue.contains(&tx1));
        assert!(!queue.contains(&tx2));
    }

    #[test]
    fn test_duplicate_insert() {
        let mut queue = PriorityQueue::new();

        let tx1 = Hash::new([1; 32]);

        assert!(queue.insert(tx1, 10, Utc::now()));
        // Second insert with same hash should fail
        assert!(!queue.insert(tx1, 20, Utc::now()));

        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut queue = PriorityQueue::new();

        queue.insert(Hash::new([1; 32]), 10, Utc::now());
        queue.insert(Hash::new([2; 32]), 20, Utc::now());

        assert_eq!(queue.len(), 2);

        queue.clear();

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_iter() {
        let mut queue = PriorityQueue::new();
        let now = Utc::now();

        let tx1 = Hash::new([1; 32]);
        let tx2 = Hash::new([2; 32]);
        let tx3 = Hash::new([3; 32]);

        queue.insert(tx1, 10, now);
        queue.insert(tx2, 30, now);
        queue.insert(tx3, 20, now);

        let hashes: Vec<Hash> = queue.iter().map(|e| e.tx_hash).collect();

        // Should be in priority order
        assert_eq!(hashes, vec![tx2, tx3, tx1]);
    }
}
