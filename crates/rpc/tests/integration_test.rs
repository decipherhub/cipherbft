//! End-to-end integration tests for the RPC server.
//!
//! These tests verify that all components work together correctly.

use alloy_primitives::{Address, Bytes, B256, U256};

use cipherbft_rpc::{
    BlockNumberOrTag, ExecutionApi, MempoolApi, NetworkApi, RpcConfig, RpcStorage,
    StubExecutionApi, StubMempoolApi, StubNetworkApi, StubRpcStorage, SubscriptionKind,
    SubscriptionManager,
};

/// Integration test: Verify all stub components can be created together.
#[test]
fn test_component_creation() {
    // Create all stub components
    let config = RpcConfig::default();
    let _storage = StubRpcStorage::default();
    let _mempool = StubMempoolApi::new();
    let _executor = StubExecutionApi::new();
    let _network = StubNetworkApi::new();
    let subscription_manager = SubscriptionManager::new();

    // Verify configuration
    assert_eq!(config.http_port, 8545);
    assert_eq!(config.ws_port, 8546);
    assert_eq!(config.chain_id, 85300);

    // Verify subscription manager
    assert_eq!(subscription_manager.subscription_count(), 0);
}

/// Integration test: Full query flow through storage.
#[tokio::test]
async fn test_storage_query_flow() {
    let storage = StubRpcStorage::new(12345);

    // Query latest block
    let block = storage.latest_block_number().await.unwrap();
    assert_eq!(block, 0);

    // Update and verify
    storage.set_latest_block(100);
    let block = storage.latest_block_number().await.unwrap();
    assert_eq!(block, 100);

    // Query sync status
    let status = storage.sync_status().await.unwrap();
    assert!(!status.is_syncing());
}

/// Integration test: Full transaction submission flow through mempool.
#[tokio::test]
async fn test_mempool_submission_flow() {
    let mempool = StubMempoolApi::new();

    // Submit transaction
    let tx_data = Bytes::from(vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    let hash1 = mempool.submit_transaction(tx_data.clone()).await.unwrap();

    // Verify hash is deterministic for same data
    let hash2 = mempool.submit_transaction(tx_data).await.unwrap();
    assert_eq!(hash1, hash2);

    // Different data should produce different hash
    let different_data = Bytes::from(vec![0xff, 0xfe, 0xfd]);
    let hash3 = mempool.submit_transaction(different_data).await.unwrap();
    assert_ne!(hash1, hash3);
}

/// Integration test: Full execution flow through executor.
#[tokio::test]
async fn test_execution_flow() {
    let executor = StubExecutionApi::new();
    let contract_addr = Address::repeat_byte(0xab);

    // Call without data
    let result = executor
        .call(
            None,
            Some(contract_addr),
            None,
            None,
            None,
            None,
            BlockNumberOrTag::Latest,
        )
        .await
        .unwrap();
    assert!(result.is_empty());

    // Estimate gas for simple transfer
    let gas = executor
        .estimate_gas(None, None, None, None, None, None, BlockNumberOrTag::Latest)
        .await
        .unwrap();
    assert_eq!(gas, 21_000);

    // Estimate gas with data
    let data = Bytes::from(vec![0u8; 50]); // 50 bytes
    let gas = executor
        .estimate_gas(
            None,
            None,
            None,
            None,
            None,
            Some(data),
            BlockNumberOrTag::Latest,
        )
        .await
        .unwrap();
    assert_eq!(gas, 21_000 + 50 * 16); // base + 16 gas per byte
}

/// Integration test: Full network API flow.
#[tokio::test]
async fn test_network_flow() {
    let mut network = StubNetworkApi::new();

    // Initial state
    assert!(network.is_listening().await.unwrap());
    assert_eq!(network.peer_count().await.unwrap(), 0);

    // Add peers
    network.set_peer_count(25);
    assert_eq!(network.peer_count().await.unwrap(), 25);

    // Stop listening
    network.set_listening(false);
    assert!(!network.is_listening().await.unwrap());
}

/// Integration test: Subscription lifecycle.
#[test]
fn test_subscription_lifecycle() {
    let manager = SubscriptionManager::new();

    // Create various subscription types
    let id1 = manager.subscribe(SubscriptionKind::NewHeads);
    let id2 = manager.subscribe(SubscriptionKind::NewPendingTransactions);
    assert_eq!(manager.subscription_count(), 2);

    // Subscriptions have unique IDs
    assert_ne!(id1.as_u64(), id2.as_u64());

    // Unsubscribe
    assert!(manager.unsubscribe(id1));
    assert_eq!(manager.subscription_count(), 1);

    // Double unsubscribe fails
    assert!(!manager.unsubscribe(id1));
    assert_eq!(manager.subscription_count(), 1);

    // Cleanup
    assert!(manager.unsubscribe(id2));
    assert_eq!(manager.subscription_count(), 0);
}

/// Integration test: Configuration validation.
#[test]
fn test_config_integration() {
    // Valid config
    let config = RpcConfig::default();
    assert!(config.validate().is_ok());

    // Custom chain ID
    let config = RpcConfig::with_chain_id(1); // mainnet
    assert_eq!(config.chain_id, 1);
    assert!(config.validate().is_ok());

    // Invalid: same port for HTTP and WS
    let mut invalid_config = RpcConfig::default();
    invalid_config.ws_port = invalid_config.http_port;
    assert!(invalid_config.validate().is_err());
}

/// Integration test: Multiple state queries at specific block.
#[tokio::test]
async fn test_state_queries_at_block() {
    let storage = StubRpcStorage::default();
    let addr = Address::repeat_byte(0x42);

    // All state queries at latest block
    let balance = storage
        .get_balance(addr, BlockNumberOrTag::Latest)
        .await
        .unwrap();
    let code = storage
        .get_code(addr, BlockNumberOrTag::Latest)
        .await
        .unwrap();
    let nonce = storage
        .get_transaction_count(addr, BlockNumberOrTag::Latest)
        .await
        .unwrap();
    let storage_val = storage
        .get_storage_at(addr, U256::from(0), BlockNumberOrTag::Latest)
        .await
        .unwrap();

    // Stub returns default values
    assert_eq!(balance, U256::ZERO);
    assert!(code.is_empty());
    assert_eq!(nonce, 0);
    assert_eq!(storage_val, B256::ZERO);
}

/// Integration test: Block queries return None for non-existent blocks.
#[tokio::test]
async fn test_block_queries() {
    let storage = StubRpcStorage::default();

    // Query by number
    let block = storage
        .get_block_by_number(BlockNumberOrTag::Latest, false)
        .await
        .unwrap();
    assert!(block.is_none());

    // Query by hash
    let block = storage.get_block_by_hash(B256::ZERO, false).await.unwrap();
    assert!(block.is_none());

    // Query specific number
    let block = storage
        .get_block_by_number(BlockNumberOrTag::Number(12345), true)
        .await
        .unwrap();
    assert!(block.is_none());
}

/// Integration test: Transaction queries return None for non-existent txs.
#[tokio::test]
async fn test_transaction_queries() {
    let storage = StubRpcStorage::default();

    // Query transaction
    let tx = storage
        .get_transaction_by_hash(B256::repeat_byte(0xab))
        .await
        .unwrap();
    assert!(tx.is_none());

    // Query receipt
    let receipt = storage
        .get_transaction_receipt(B256::repeat_byte(0xcd))
        .await
        .unwrap();
    assert!(receipt.is_none());
}
