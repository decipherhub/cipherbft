//! Log storage trait for event indexing and eth_getLogs queries.
//!
//! This module provides the [`LogStore`] trait for storing and querying
//! transaction logs/events. The RPC layer uses this interface to serve
//! `eth_getLogs` and filter-based subscription requests.
//!
//! # Indexing Strategy
//!
//! Logs are indexed by:
//! - Block number (primary ordering)
//! - Contract address (for address-filtered queries)
//! - Topics (for topic-filtered queries)
//!
//! This enables efficient range queries with any combination of filters.

use async_trait::async_trait;

use crate::error::StorageError;

/// Result type for log storage operations.
pub type LogStoreResult<T> = Result<T, StorageError>;

/// Log entry for storage and retrieval.
///
/// This is the canonical representation of an Ethereum log/event
/// stored in the database with full context for reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLog {
    /// Contract address that emitted the log (20 bytes)
    pub address: [u8; 20],
    /// Indexed topics (up to 4, each 32 bytes)
    pub topics: Vec<[u8; 32]>,
    /// Non-indexed log data
    pub data: Vec<u8>,
    /// Block number where this log was emitted
    pub block_number: u64,
    /// Block hash (32 bytes)
    pub block_hash: [u8; 32],
    /// Transaction hash that generated this log (32 bytes)
    pub transaction_hash: [u8; 32],
    /// Transaction index within the block
    pub transaction_index: u32,
    /// Log index within the block
    pub log_index: u32,
    /// Whether this log was removed due to a reorg
    pub removed: bool,
}

/// Filter criteria for log queries.
///
/// Mirrors the Ethereum JSON-RPC `eth_getLogs` filter specification.
/// All fields are optional and combine with AND semantics.
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    /// Start block (inclusive). None means from earliest.
    pub from_block: Option<u64>,
    /// End block (inclusive). None means to latest.
    pub to_block: Option<u64>,
    /// Specific block hash. If set, from_block and to_block are ignored.
    pub block_hash: Option<[u8; 32]>,
    /// Contract addresses to filter by. Empty means any address.
    pub addresses: Vec<[u8; 20]>,
    /// Topics filter. Each position can be:
    /// - None: match any topic at this position
    /// - Some(vec): match any of the topics in the vec at this position
    ///
    /// Outer vec has up to 4 elements (topic0..topic3).
    /// Inner vec contains allowed values for that position.
    pub topics: Vec<Option<Vec<[u8; 32]>>>,
}

impl LogFilter {
    /// Create a new empty filter (matches all logs).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the block range.
    pub fn with_block_range(mut self, from: Option<u64>, to: Option<u64>) -> Self {
        self.from_block = from;
        self.to_block = to;
        self
    }

    /// Set a specific block hash filter.
    pub fn with_block_hash(mut self, hash: [u8; 32]) -> Self {
        self.block_hash = Some(hash);
        self
    }

    /// Add a single address filter.
    pub fn with_address(mut self, address: [u8; 20]) -> Self {
        self.addresses.push(address);
        self
    }

    /// Set multiple address filters.
    pub fn with_addresses(mut self, addresses: Vec<[u8; 20]>) -> Self {
        self.addresses = addresses;
        self
    }

    /// Set topic filters.
    pub fn with_topics(mut self, topics: Vec<Option<Vec<[u8; 32]>>>) -> Self {
        self.topics = topics;
        self
    }

    /// Check if this filter matches a given log.
    pub fn matches(&self, log: &StoredLog) -> bool {
        // Check block hash if specified
        if let Some(ref hash) = self.block_hash {
            if &log.block_hash != hash {
                return false;
            }
        }

        // Check block range
        if let Some(from) = self.from_block {
            if log.block_number < from {
                return false;
            }
        }
        if let Some(to) = self.to_block {
            if log.block_number > to {
                return false;
            }
        }

        // Check addresses
        if !self.addresses.is_empty() && !self.addresses.contains(&log.address) {
            return false;
        }

        // Check topics
        for (i, topic_filter) in self.topics.iter().enumerate() {
            if let Some(allowed_topics) = topic_filter {
                // If we have a filter for this position, the log must have a topic there
                if i >= log.topics.len() {
                    return false;
                }
                // The topic must match one of the allowed values
                if !allowed_topics.contains(&log.topics[i]) {
                    return false;
                }
            }
            // None means any topic (or no topic) is acceptable at this position
        }

        true
    }
}

/// Trait for storing and querying transaction logs.
///
/// This trait provides async storage operations for transaction logs/events.
/// Logs are indexed for efficient eth_getLogs queries with various filter
/// combinations.
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access from multiple RPC handlers.
#[async_trait]
pub trait LogStore: Send + Sync {
    /// Store logs for a transaction.
    ///
    /// The logs are indexed by block number, address, and topics.
    ///
    /// # Arguments
    /// * `logs` - The logs to store
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn put_logs(&self, logs: &[StoredLog]) -> LogStoreResult<()>;

    /// Query logs matching the given filter.
    ///
    /// Returns logs in ascending order by (block_number, log_index).
    ///
    /// # Arguments
    /// * `filter` - The filter criteria
    /// * `max_results` - Maximum number of logs to return (for pagination/DoS prevention)
    ///
    /// # Returns
    /// * `Ok(logs)` - Matching logs in order
    /// * `Err(...)` if the storage operation fails
    async fn get_logs(
        &self,
        filter: &LogFilter,
        max_results: usize,
    ) -> LogStoreResult<Vec<StoredLog>>;

    /// Get all logs for a specific block.
    ///
    /// This is more efficient than using get_logs with a single block range
    /// when you need all logs for a block.
    ///
    /// # Arguments
    /// * `block_number` - The block number
    ///
    /// # Returns
    /// * `Ok(logs)` - All logs for the block in order
    /// * `Err(...)` if the storage operation fails
    async fn get_logs_by_block(&self, block_number: u64) -> LogStoreResult<Vec<StoredLog>>;

    /// Get logs for a specific block by hash.
    ///
    /// # Arguments
    /// * `block_hash` - The block hash (32 bytes)
    ///
    /// # Returns
    /// * `Ok(logs)` - All logs for the block in order
    /// * `Err(...)` if the storage operation fails
    async fn get_logs_by_block_hash(&self, block_hash: &[u8; 32])
        -> LogStoreResult<Vec<StoredLog>>;

    /// Delete all logs for a block (for pruning or reorg handling).
    ///
    /// # Arguments
    /// * `block_number` - The block number to delete logs for
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    /// Does not return an error if no logs exist for the block.
    async fn delete_logs_by_block(&self, block_number: u64) -> LogStoreResult<()>;

    /// Get the bloom filter for a block.
    ///
    /// The bloom filter is a probabilistic data structure for fast
    /// negative lookups. If a log doesn't match the bloom, it
    /// definitely doesn't exist in the block.
    ///
    /// # Arguments
    /// * `block_number` - The block number
    ///
    /// # Returns
    /// * `Ok(Some(bloom))` - The bloom filter (256 bytes)
    /// * `Ok(None)` if no bloom exists for the block
    /// * `Err(...)` if the storage operation fails
    async fn get_block_bloom(&self, block_number: u64) -> LogStoreResult<Option<[u8; 256]>>;

    /// Store the bloom filter for a block.
    ///
    /// # Arguments
    /// * `block_number` - The block number
    /// * `bloom` - The bloom filter (256 bytes)
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn put_block_bloom(&self, block_number: u64, bloom: &[u8; 256]) -> LogStoreResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_log(block_number: u64, log_index: u32, address: u8) -> StoredLog {
        StoredLog {
            address: [address; 20],
            topics: vec![[1u8; 32], [2u8; 32]],
            data: vec![0xab, 0xcd],
            block_number,
            block_hash: [0x11; 32],
            transaction_hash: [0x22; 32],
            transaction_index: 0,
            log_index,
            removed: false,
        }
    }

    #[test]
    fn test_log_filter_block_range() {
        let log = make_test_log(100, 0, 1);

        // Match within range
        let filter = LogFilter::new().with_block_range(Some(50), Some(150));
        assert!(filter.matches(&log));

        // Before range
        let filter = LogFilter::new().with_block_range(Some(150), Some(200));
        assert!(!filter.matches(&log));

        // After range
        let filter = LogFilter::new().with_block_range(Some(50), Some(99));
        assert!(!filter.matches(&log));
    }

    #[test]
    fn test_log_filter_address() {
        let log = make_test_log(100, 0, 1);

        // Matching address
        let filter = LogFilter::new().with_address([1u8; 20]);
        assert!(filter.matches(&log));

        // Non-matching address
        let filter = LogFilter::new().with_address([2u8; 20]);
        assert!(!filter.matches(&log));

        // Multiple addresses (OR)
        let filter = LogFilter::new().with_addresses(vec![[2u8; 20], [1u8; 20]]);
        assert!(filter.matches(&log));
    }

    #[test]
    fn test_log_filter_topics() {
        let log = make_test_log(100, 0, 1);

        // Match topic0
        let filter = LogFilter::new().with_topics(vec![Some(vec![[1u8; 32]])]);
        assert!(filter.matches(&log));

        // Non-matching topic0
        let filter = LogFilter::new().with_topics(vec![Some(vec![[99u8; 32]])]);
        assert!(!filter.matches(&log));

        // Match topic1, any topic0
        let filter = LogFilter::new().with_topics(vec![None, Some(vec![[2u8; 32]])]);
        assert!(filter.matches(&log));

        // Topic filter beyond log's topics
        let filter = LogFilter::new().with_topics(vec![None, None, None, Some(vec![[3u8; 32]])]);
        assert!(!filter.matches(&log));
    }

    #[test]
    fn test_log_filter_combined() {
        let log = make_test_log(100, 0, 1);

        // All conditions match
        let filter = LogFilter::new()
            .with_block_range(Some(50), Some(150))
            .with_address([1u8; 20])
            .with_topics(vec![Some(vec![[1u8; 32]])]);
        assert!(filter.matches(&log));

        // One condition fails
        let filter = LogFilter::new()
            .with_block_range(Some(50), Some(150))
            .with_address([2u8; 20]) // Wrong address
            .with_topics(vec![Some(vec![[1u8; 32]])]);
        assert!(!filter.matches(&log));
    }
}
