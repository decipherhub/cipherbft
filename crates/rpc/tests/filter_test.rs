//! Integration tests for Ethereum filter API methods.
//!
//! Tests the filter RPC methods: eth_newFilter, eth_newBlockFilter,
//! eth_newPendingTransactionFilter, eth_getFilterChanges, eth_getFilterLogs,
//! and eth_uninstallFilter.

use std::sync::Arc;

use alloy_primitives::{B256, U256};
use alloy_rpc_types_eth::Filter;
use cipherbft_rpc::{
    EthRpcServer, FilterManager, RpcConfig, StubExecutionApi, StubMempoolApi, StubRpcStorage,
};
use jsonrpsee::core::RpcResult;

/// Create a test EthApi instance with filter support.
fn create_test_api() -> impl EthRpcServer {
    let storage = Arc::new(StubRpcStorage::default());
    let mempool = Arc::new(StubMempoolApi::new());
    let executor = Arc::new(StubExecutionApi::new());
    let config = Arc::new(RpcConfig::with_chain_id(85300));
    let filter_manager = Arc::new(FilterManager::new());

    cipherbft_rpc::eth::EthApi::with_filter_manager(
        storage,
        mempool,
        executor,
        config,
        filter_manager,
    )
}

/// Create a test EthApi with a shared filter manager.
fn create_test_api_with_manager(filter_manager: Arc<FilterManager>) -> impl EthRpcServer {
    let storage = Arc::new(StubRpcStorage::default());
    let mempool = Arc::new(StubMempoolApi::new());
    let executor = Arc::new(StubExecutionApi::new());
    let config = Arc::new(RpcConfig::with_chain_id(85300));

    cipherbft_rpc::eth::EthApi::with_filter_manager(
        storage,
        mempool,
        executor,
        config,
        filter_manager,
    )
}

// ===== eth_newFilter tests =====

#[tokio::test]
async fn test_new_filter_creates_log_filter() {
    let api = create_test_api();
    let filter = Filter::default();

    let result: RpcResult<U256> = api.new_filter(filter).await;
    assert!(result.is_ok());

    let filter_id = result.unwrap();
    assert!(filter_id > U256::ZERO, "Filter ID should be positive");
}

#[tokio::test]
async fn test_new_filter_returns_unique_ids() {
    let api = create_test_api();

    let id1: U256 = api.new_filter(Filter::default()).await.unwrap();
    let id2: U256 = api.new_filter(Filter::default()).await.unwrap();
    let id3: U256 = api.new_filter(Filter::default()).await.unwrap();

    assert_ne!(id1, id2, "Filter IDs should be unique");
    assert_ne!(id2, id3, "Filter IDs should be unique");
    assert_ne!(id1, id3, "Filter IDs should be unique");
}

// ===== eth_newBlockFilter tests =====

#[tokio::test]
async fn test_new_block_filter() {
    let api = create_test_api();

    let result: RpcResult<U256> = api.new_block_filter().await;
    assert!(result.is_ok());

    let filter_id = result.unwrap();
    assert!(filter_id > U256::ZERO, "Block filter ID should be positive");
}

#[tokio::test]
async fn test_multiple_block_filters() {
    let api = create_test_api();

    let id1 = api.new_block_filter().await.unwrap();
    let id2 = api.new_block_filter().await.unwrap();

    assert_ne!(id1, id2, "Block filter IDs should be unique");
}

// ===== eth_newPendingTransactionFilter tests =====

#[tokio::test]
async fn test_new_pending_transaction_filter() {
    let api = create_test_api();

    let result: RpcResult<U256> = api.new_pending_transaction_filter().await;
    assert!(result.is_ok());

    let filter_id = result.unwrap();
    assert!(
        filter_id > U256::ZERO,
        "Pending tx filter ID should be positive"
    );
}

// ===== eth_getFilterChanges tests =====

#[tokio::test]
async fn test_get_filter_changes_empty_log_filter() {
    let api = create_test_api();

    // Create a log filter
    let filter_id = api.new_filter(Filter::default()).await.unwrap();

    // Get changes - should return empty array (no logs in stub storage)
    let changes = api.get_filter_changes(filter_id).await.unwrap();

    // Should be an array (possibly empty)
    assert!(changes.is_array(), "Changes should be an array");
}

#[tokio::test]
async fn test_get_filter_changes_block_filter() {
    let filter_manager = Arc::new(FilterManager::new());
    let api = create_test_api_with_manager(Arc::clone(&filter_manager));

    // Create a block filter
    let filter_id = api.new_block_filter().await.unwrap();

    // Simulate new blocks by notifying the filter manager
    let block_hash1 = B256::repeat_byte(0x11);
    let block_hash2 = B256::repeat_byte(0x22);
    filter_manager.notify_new_block(block_hash1);
    filter_manager.notify_new_block(block_hash2);

    // Get changes - should return the block hashes
    let changes = api.get_filter_changes(filter_id).await.unwrap();

    let hashes: Vec<B256> = serde_json::from_value(changes).unwrap();
    assert_eq!(hashes.len(), 2);
    assert!(hashes.contains(&block_hash1));
    assert!(hashes.contains(&block_hash2));

    // Second call should return empty (changes consumed)
    let changes2 = api.get_filter_changes(filter_id).await.unwrap();
    let hashes2: Vec<B256> = serde_json::from_value(changes2).unwrap();
    assert!(
        hashes2.is_empty(),
        "Changes should be consumed after first call"
    );
}

#[tokio::test]
async fn test_get_filter_changes_pending_tx_filter() {
    let filter_manager = Arc::new(FilterManager::new());
    let api = create_test_api_with_manager(Arc::clone(&filter_manager));

    // Create a pending tx filter
    let filter_id = api.new_pending_transaction_filter().await.unwrap();

    // Simulate pending transactions
    let tx_hash = B256::repeat_byte(0x33);
    filter_manager.notify_pending_tx(tx_hash);

    // Get changes
    let changes = api.get_filter_changes(filter_id).await.unwrap();
    let hashes: Vec<B256> = serde_json::from_value(changes).unwrap();

    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0], tx_hash);
}

#[tokio::test]
async fn test_get_filter_changes_nonexistent_filter() {
    let api = create_test_api();

    // Try to get changes for a filter that doesn't exist
    let nonexistent_id = U256::from(999999);
    let result = api.get_filter_changes(nonexistent_id).await;

    assert!(result.is_err(), "Should fail for nonexistent filter");
}

// ===== eth_getFilterLogs tests =====

#[tokio::test]
async fn test_get_filter_logs_log_filter() {
    let api = create_test_api();

    // Create a log filter
    let filter_id = api.new_filter(Filter::default()).await.unwrap();

    // Get all logs matching the filter
    let logs = api.get_filter_logs(filter_id).await.unwrap();

    // Should return logs (empty in stub storage)
    assert!(logs.is_empty(), "Stub storage has no logs");
}

#[tokio::test]
async fn test_get_filter_logs_wrong_filter_type() {
    let api = create_test_api();

    // Create a block filter (not a log filter)
    let filter_id = api.new_block_filter().await.unwrap();

    // Try to get logs - should fail (only valid for log filters)
    let result = api.get_filter_logs(filter_id).await;

    assert!(
        result.is_err(),
        "eth_getFilterLogs should fail for block filters"
    );
}

#[tokio::test]
async fn test_get_filter_logs_nonexistent_filter() {
    let api = create_test_api();

    // Try to get logs for a filter that doesn't exist
    let nonexistent_id = U256::from(999999);
    let result = api.get_filter_logs(nonexistent_id).await;

    assert!(result.is_err(), "Should fail for nonexistent filter");
}

// ===== eth_uninstallFilter tests =====

#[tokio::test]
async fn test_uninstall_filter_success() {
    let api = create_test_api();

    // Create a filter
    let filter_id = api.new_filter(Filter::default()).await.unwrap();

    // Uninstall it
    let result = api.uninstall_filter(filter_id).await.unwrap();
    assert!(result, "Uninstall should return true for existing filter");

    // Try to use it again - should fail
    let changes_result = api.get_filter_changes(filter_id).await;
    assert!(changes_result.is_err(), "Filter should no longer exist");
}

#[tokio::test]
async fn test_uninstall_filter_twice() {
    let api = create_test_api();

    // Create and uninstall a filter
    let filter_id = api.new_filter(Filter::default()).await.unwrap();
    let first_uninstall = api.uninstall_filter(filter_id).await.unwrap();
    assert!(first_uninstall, "First uninstall should succeed");

    // Second uninstall should return false
    let second_uninstall = api.uninstall_filter(filter_id).await.unwrap();
    assert!(!second_uninstall, "Second uninstall should return false");
}

#[tokio::test]
async fn test_uninstall_nonexistent_filter() {
    let api = create_test_api();

    // Try to uninstall a filter that was never created
    let nonexistent_id = U256::from(999999);
    let result = api.uninstall_filter(nonexistent_id).await.unwrap();

    assert!(
        !result,
        "Uninstall should return false for nonexistent filter"
    );
}

// ===== Mixed filter type tests =====

#[tokio::test]
async fn test_different_filter_types_coexist() {
    let filter_manager = Arc::new(FilterManager::new());
    let api = create_test_api_with_manager(Arc::clone(&filter_manager));

    // Create one of each filter type
    let log_filter_id = api.new_filter(Filter::default()).await.unwrap();
    let block_filter_id = api.new_block_filter().await.unwrap();
    let pending_tx_filter_id = api.new_pending_transaction_filter().await.unwrap();

    // All IDs should be unique
    assert_ne!(log_filter_id, block_filter_id);
    assert_ne!(block_filter_id, pending_tx_filter_id);
    assert_ne!(log_filter_id, pending_tx_filter_id);

    // Notify both block and pending tx
    let block_hash = B256::repeat_byte(0xAA);
    let tx_hash = B256::repeat_byte(0xBB);
    filter_manager.notify_new_block(block_hash);
    filter_manager.notify_pending_tx(tx_hash);

    // Each filter should return its own changes
    let block_changes = api.get_filter_changes(block_filter_id).await.unwrap();
    let block_hashes: Vec<B256> = serde_json::from_value(block_changes).unwrap();
    assert_eq!(block_hashes.len(), 1);
    assert_eq!(block_hashes[0], block_hash);

    let tx_changes = api.get_filter_changes(pending_tx_filter_id).await.unwrap();
    let tx_hashes: Vec<B256> = serde_json::from_value(tx_changes).unwrap();
    assert_eq!(tx_hashes.len(), 1);
    assert_eq!(tx_hashes[0], tx_hash);

    // Log filter returns logs (empty from stub)
    let log_changes = api.get_filter_changes(log_filter_id).await.unwrap();
    assert!(log_changes.is_array());
}

// ===== Filter lifecycle tests =====

#[tokio::test]
async fn test_filter_persists_across_polls() {
    let filter_manager = Arc::new(FilterManager::new());
    let api = create_test_api_with_manager(Arc::clone(&filter_manager));

    let filter_id = api.new_block_filter().await.unwrap();

    // First poll - empty
    let changes1 = api.get_filter_changes(filter_id).await.unwrap();
    let hashes1: Vec<B256> = serde_json::from_value(changes1).unwrap();
    assert!(hashes1.is_empty());

    // Add a block
    filter_manager.notify_new_block(B256::repeat_byte(0x01));

    // Second poll - one block
    let changes2 = api.get_filter_changes(filter_id).await.unwrap();
    let hashes2: Vec<B256> = serde_json::from_value(changes2).unwrap();
    assert_eq!(hashes2.len(), 1);

    // Add more blocks
    filter_manager.notify_new_block(B256::repeat_byte(0x02));
    filter_manager.notify_new_block(B256::repeat_byte(0x03));

    // Third poll - two more blocks
    let changes3 = api.get_filter_changes(filter_id).await.unwrap();
    let hashes3: Vec<B256> = serde_json::from_value(changes3).unwrap();
    assert_eq!(hashes3.len(), 2);

    // Filter still works after multiple polls
    filter_manager.notify_new_block(B256::repeat_byte(0x04));
    let changes4 = api.get_filter_changes(filter_id).await.unwrap();
    let hashes4: Vec<B256> = serde_json::from_value(changes4).unwrap();
    assert_eq!(hashes4.len(), 1);
}
