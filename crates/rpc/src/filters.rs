//! Filter management for eth_newFilter and related RPC methods.
//!
//! This module provides the [`FilterManager`] for handling Ethereum filter RPCs:
//! - `eth_newFilter` - Create log filter
//! - `eth_newBlockFilter` - Create block filter
//! - `eth_newPendingTransactionFilter` - Create pending tx filter
//! - `eth_getFilterChanges` - Get updates since last poll
//! - `eth_getFilterLogs` - Get all logs matching filter
//! - `eth_uninstallFilter` - Remove filter

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use alloy_primitives::{B256, U256};
use alloy_rpc_types_eth::{Filter, Log};
use parking_lot::RwLock;

/// Default filter timeout (5 minutes per Ethereum spec).
pub const DEFAULT_FILTER_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum number of filters per connection to prevent DoS.
pub const MAX_FILTERS: usize = 1000;

/// Filter type variants.
#[derive(Debug, Clone)]
pub enum FilterType {
    /// Log filter with the original filter criteria.
    Log(Filter),
    /// Block filter (watches for new block hashes).
    Block,
    /// Pending transaction filter (watches for new pending tx hashes).
    PendingTransaction,
}

/// Internal filter state.
#[derive(Debug)]
struct FilterState {
    /// The filter type and criteria.
    filter_type: FilterType,
    /// Last block number seen (for incremental updates).
    last_block: u64,
    /// Last log index seen within the last block.
    last_log_index: u32,
    /// When this filter was last accessed.
    last_accessed: Instant,
    /// Accumulated block hashes (for block filters).
    pending_block_hashes: Vec<B256>,
    /// Accumulated tx hashes (for pending tx filters).
    pending_tx_hashes: Vec<B256>,
}

impl FilterState {
    fn new(filter_type: FilterType, current_block: u64) -> Self {
        Self {
            filter_type,
            last_block: current_block,
            last_log_index: 0,
            last_accessed: Instant::now(),
            pending_block_hashes: Vec::new(),
            pending_tx_hashes: Vec::new(),
        }
    }

    fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.last_accessed.elapsed() > timeout
    }
}

/// Result type for filter changes.
#[derive(Debug, Clone)]
pub enum FilterChanges {
    /// Log entries for log filters.
    Logs(Vec<Log>),
    /// Block hashes for block filters.
    BlockHashes(Vec<B256>),
    /// Transaction hashes for pending transaction filters.
    TxHashes(Vec<B256>),
}

/// Manages Ethereum filters for JSON-RPC.
///
/// This struct handles the lifecycle of filters created via `eth_newFilter`,
/// `eth_newBlockFilter`, and `eth_newPendingTransactionFilter`.
///
/// # Thread Safety
///
/// The manager is thread-safe and can be shared across RPC handlers.
pub struct FilterManager {
    /// Active filters keyed by filter ID.
    filters: RwLock<HashMap<U256, FilterState>>,
    /// Next filter ID counter.
    next_id: AtomicU64,
    /// Filter timeout duration.
    timeout: Duration,
}

impl FilterManager {
    /// Create a new filter manager.
    pub fn new() -> Self {
        Self {
            filters: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            timeout: DEFAULT_FILTER_TIMEOUT,
        }
    }

    /// Create a new filter manager with custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            filters: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            timeout,
        }
    }

    /// Create a new log filter.
    ///
    /// Returns the filter ID on success, or None if max filters exceeded.
    pub fn new_log_filter(&self, filter: Filter, current_block: u64) -> Option<U256> {
        self.create_filter(FilterType::Log(filter), current_block)
    }

    /// Create a new block filter.
    ///
    /// Returns the filter ID on success, or None if max filters exceeded.
    pub fn new_block_filter(&self, current_block: u64) -> Option<U256> {
        self.create_filter(FilterType::Block, current_block)
    }

    /// Create a new pending transaction filter.
    ///
    /// Returns the filter ID on success, or None if max filters exceeded.
    pub fn new_pending_transaction_filter(&self, current_block: u64) -> Option<U256> {
        self.create_filter(FilterType::PendingTransaction, current_block)
    }

    /// Internal helper to create a filter.
    fn create_filter(&self, filter_type: FilterType, current_block: u64) -> Option<U256> {
        // Clean up expired filters first
        self.cleanup_expired();

        let mut filters = self.filters.write();

        // Check max filters limit
        if filters.len() >= MAX_FILTERS {
            return None;
        }

        let id = U256::from(self.next_id.fetch_add(1, Ordering::Relaxed));
        let state = FilterState::new(filter_type, current_block);
        filters.insert(id, state);

        Some(id)
    }

    /// Get filter type for a given filter ID.
    ///
    /// Returns None if filter doesn't exist or is expired.
    pub fn get_filter_type(&self, filter_id: U256) -> Option<FilterType> {
        let mut filters = self.filters.write();
        let state = filters.get_mut(&filter_id)?;

        if state.is_expired(self.timeout) {
            filters.remove(&filter_id);
            return None;
        }

        state.touch();
        Some(state.filter_type.clone())
    }

    /// Get the last block seen by a filter.
    pub fn get_last_block(&self, filter_id: U256) -> Option<u64> {
        let filters = self.filters.read();
        filters.get(&filter_id).map(|s| s.last_block)
    }

    /// Update filter state after fetching logs.
    ///
    /// Call this after successfully fetching logs to update the "last seen" position.
    pub fn update_log_filter(&self, filter_id: U256, new_block: u64, new_log_index: u32) {
        let mut filters = self.filters.write();
        if let Some(state) = filters.get_mut(&filter_id) {
            state.last_block = new_block;
            state.last_log_index = new_log_index;
            state.touch();
        }
    }

    /// Add a new block hash for block filters.
    ///
    /// This should be called when a new block is added to the chain.
    pub fn notify_new_block(&self, block_hash: B256) {
        let mut filters = self.filters.write();
        for state in filters.values_mut() {
            if matches!(state.filter_type, FilterType::Block) {
                state.pending_block_hashes.push(block_hash);
            }
        }
    }

    /// Add a new pending transaction hash for pending tx filters.
    ///
    /// This should be called when a new pending tx is received.
    pub fn notify_pending_tx(&self, tx_hash: B256) {
        let mut filters = self.filters.write();
        for state in filters.values_mut() {
            if matches!(state.filter_type, FilterType::PendingTransaction) {
                state.pending_tx_hashes.push(tx_hash);
            }
        }
    }

    /// Get and clear pending block hashes for a block filter.
    pub fn take_block_hashes(&self, filter_id: U256) -> Option<Vec<B256>> {
        let mut filters = self.filters.write();
        let state = filters.get_mut(&filter_id)?;

        if state.is_expired(self.timeout) {
            filters.remove(&filter_id);
            return None;
        }

        if !matches!(state.filter_type, FilterType::Block) {
            return None;
        }

        state.touch();
        let hashes = std::mem::take(&mut state.pending_block_hashes);
        Some(hashes)
    }

    /// Get and clear pending transaction hashes for a pending tx filter.
    pub fn take_pending_tx_hashes(&self, filter_id: U256) -> Option<Vec<B256>> {
        let mut filters = self.filters.write();
        let state = filters.get_mut(&filter_id)?;

        if state.is_expired(self.timeout) {
            filters.remove(&filter_id);
            return None;
        }

        if !matches!(state.filter_type, FilterType::PendingTransaction) {
            return None;
        }

        state.touch();
        let hashes = std::mem::take(&mut state.pending_tx_hashes);
        Some(hashes)
    }

    /// Uninstall a filter.
    ///
    /// Returns true if the filter existed and was removed.
    pub fn uninstall_filter(&self, filter_id: U256) -> bool {
        self.filters.write().remove(&filter_id).is_some()
    }

    /// Check if a filter exists and is valid.
    pub fn filter_exists(&self, filter_id: U256) -> bool {
        let mut filters = self.filters.write();
        if let Some(state) = filters.get(&filter_id) {
            if state.is_expired(self.timeout) {
                filters.remove(&filter_id);
                return false;
            }
            return true;
        }
        false
    }

    /// Get the number of active filters.
    pub fn filter_count(&self) -> usize {
        self.filters.read().len()
    }

    /// Clean up expired filters.
    pub fn cleanup_expired(&self) {
        let mut filters = self.filters.write();
        filters.retain(|_, state| !state.is_expired(self.timeout));
    }
}

impl Default for FilterManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_log_filter() {
        let manager = FilterManager::new();
        let filter = Filter::default();

        let id = manager.new_log_filter(filter.clone(), 100);
        assert!(id.is_some());

        let filter_type = manager.get_filter_type(id.unwrap());
        assert!(matches!(filter_type, Some(FilterType::Log(_))));
    }

    #[test]
    fn test_create_block_filter() {
        let manager = FilterManager::new();

        let id = manager.new_block_filter(100);
        assert!(id.is_some());

        let filter_type = manager.get_filter_type(id.unwrap());
        assert!(matches!(filter_type, Some(FilterType::Block)));
    }

    #[test]
    fn test_create_pending_tx_filter() {
        let manager = FilterManager::new();

        let id = manager.new_pending_transaction_filter(100);
        assert!(id.is_some());

        let filter_type = manager.get_filter_type(id.unwrap());
        assert!(matches!(filter_type, Some(FilterType::PendingTransaction)));
    }

    #[test]
    fn test_uninstall_filter() {
        let manager = FilterManager::new();

        let id = manager.new_block_filter(100).unwrap();
        assert!(manager.filter_exists(id));

        assert!(manager.uninstall_filter(id));
        assert!(!manager.filter_exists(id));

        // Uninstalling again should return false
        assert!(!manager.uninstall_filter(id));
    }

    #[test]
    fn test_notify_new_block() {
        let manager = FilterManager::new();

        let id = manager.new_block_filter(100).unwrap();
        let block_hash = B256::repeat_byte(0x11);

        manager.notify_new_block(block_hash);

        let hashes = manager.take_block_hashes(id).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], block_hash);

        // Second call should return empty
        let hashes2 = manager.take_block_hashes(id).unwrap();
        assert!(hashes2.is_empty());
    }

    #[test]
    fn test_notify_pending_tx() {
        let manager = FilterManager::new();

        let id = manager.new_pending_transaction_filter(100).unwrap();
        let tx_hash = B256::repeat_byte(0x22);

        manager.notify_pending_tx(tx_hash);

        let hashes = manager.take_pending_tx_hashes(id).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], tx_hash);

        // Second call should return empty
        let hashes2 = manager.take_pending_tx_hashes(id).unwrap();
        assert!(hashes2.is_empty());
    }

    #[test]
    fn test_filter_expiry() {
        let manager = FilterManager::with_timeout(Duration::from_millis(10));

        let id = manager.new_block_filter(100).unwrap();
        assert!(manager.filter_exists(id));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(20));

        assert!(!manager.filter_exists(id));
    }

    #[test]
    fn test_max_filters() {
        let manager = FilterManager::new();

        // Create MAX_FILTERS filters
        for _ in 0..MAX_FILTERS {
            assert!(manager.new_block_filter(100).is_some());
        }

        // Next one should fail
        assert!(manager.new_block_filter(100).is_none());
    }

    #[test]
    fn test_update_log_filter() {
        let manager = FilterManager::new();
        let filter = Filter::default();

        let id = manager.new_log_filter(filter, 100).unwrap();
        assert_eq!(manager.get_last_block(id), Some(100));

        manager.update_log_filter(id, 150, 5);
        assert_eq!(manager.get_last_block(id), Some(150));
    }

    #[test]
    fn test_filter_count() {
        let manager = FilterManager::new();

        assert_eq!(manager.filter_count(), 0);

        manager.new_block_filter(100);
        assert_eq!(manager.filter_count(), 1);

        manager.new_block_filter(100);
        assert_eq!(manager.filter_count(), 2);
    }

    #[test]
    fn test_cleanup_expired() {
        let manager = FilterManager::with_timeout(Duration::from_millis(10));

        manager.new_block_filter(100);
        manager.new_block_filter(100);
        assert_eq!(manager.filter_count(), 2);

        std::thread::sleep(Duration::from_millis(20));

        manager.cleanup_expired();
        assert_eq!(manager.filter_count(), 0);
    }
}
