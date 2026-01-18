//! Integration tests for eth_* RPC handlers.

use alloy_primitives::{Address, Bytes, B256, U256};

use cipherbft_rpc::{
    BlockNumberOrTag, ExecutionApi, MempoolApi, NetworkApi, RpcConfig, RpcStorage,
    StubExecutionApi, StubMempoolApi, StubNetworkApi, StubRpcStorage, SyncStatus,
};

/// Test that eth_chainId returns the configured chain ID.
#[test]
fn test_chain_id_configured() {
    let config = RpcConfig::with_chain_id(12345);
    assert_eq!(config.chain_id, 12345);
}

/// Test that default config has sensible values.
#[test]
fn test_default_config() {
    let config = RpcConfig::default();
    assert_eq!(config.http_port, 8545);
    assert_eq!(config.ws_port, 8546);
    assert_eq!(config.chain_id, 85300);
    assert_eq!(config.max_connections, 100);
    assert_eq!(config.rate_limit_per_ip, 1000);
}

/// Test config validation catches invalid settings.
#[test]
fn test_config_validation() {
    let mut config = RpcConfig::default();

    // Same port for HTTP and WS should fail
    config.ws_port = config.http_port;
    assert!(config.validate().is_err());

    // Zero max connections should fail
    config.ws_port = 8546;
    config.max_connections = 0;
    assert!(config.validate().is_err());
}

/// Test stub storage behavior.
#[tokio::test]
async fn test_stub_storage_latest_block() {
    let mut storage = StubRpcStorage::new(85300);

    // Default should be 0
    let block = storage.latest_block_number().await.unwrap();
    assert_eq!(block, 0);

    // After setting, should return new value
    storage.set_latest_block(100);
    let block = storage.latest_block_number().await.unwrap();
    assert_eq!(block, 100);
}

/// Test stub storage returns None for non-existent blocks.
#[tokio::test]
async fn test_stub_storage_missing_block() {
    let storage = StubRpcStorage::default();

    let block = storage
        .get_block_by_number(BlockNumberOrTag::Latest, false)
        .await
        .unwrap();
    assert!(block.is_none());

    let block = storage.get_block_by_hash(B256::ZERO, false).await.unwrap();
    assert!(block.is_none());
}

/// Test stub storage returns default values for state queries.
#[tokio::test]
async fn test_stub_storage_state_queries() {
    let storage = StubRpcStorage::default();
    let addr = Address::repeat_byte(0x42);

    // Balance should be zero
    let balance = storage
        .get_balance(addr, BlockNumberOrTag::Latest)
        .await
        .unwrap();
    assert_eq!(balance, U256::ZERO);

    // Code should be empty
    let code = storage
        .get_code(addr, BlockNumberOrTag::Latest)
        .await
        .unwrap();
    assert!(code.is_empty());

    // Nonce should be zero
    let nonce = storage
        .get_transaction_count(addr, BlockNumberOrTag::Latest)
        .await
        .unwrap();
    assert_eq!(nonce, 0);
}

/// Test stub mempool returns hash on submit.
#[tokio::test]
async fn test_stub_mempool_submit() {
    let mempool = StubMempoolApi::new();

    // Submit some bytes
    let tx_bytes = Bytes::from(vec![0x01, 0x02, 0x03, 0x04]);
    let hash = mempool.submit_transaction(tx_bytes.clone()).await.unwrap();

    // Hash should be non-zero
    assert!(!hash.is_zero());

    // Same bytes should produce same hash
    let hash2 = mempool.submit_transaction(tx_bytes).await.unwrap();
    assert_eq!(hash, hash2);
}

/// Test stub execution gas estimation.
#[tokio::test]
async fn test_stub_execution_estimate_gas() {
    let executor = StubExecutionApi::new();

    // Simple transfer (no data) = 21000 gas
    let gas = executor
        .estimate_gas(None, None, None, None, None, None, BlockNumberOrTag::Latest)
        .await
        .unwrap();
    assert_eq!(gas, 21_000);

    // With data, should include data cost
    let data = Bytes::from(vec![0u8; 100]); // 100 bytes of data
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
    assert_eq!(gas, 21_000 + 100 * 16); // base + 16 gas per byte
}

/// Test stub network API.
#[tokio::test]
async fn test_stub_network_api() {
    let mut network = StubNetworkApi::new();

    // Default should be listening with 0 peers
    assert!(network.is_listening().await.unwrap());
    assert_eq!(network.peer_count().await.unwrap(), 0);

    // Test with peers
    let network_with_peers = StubNetworkApi::with_peers(5);
    assert_eq!(network_with_peers.peer_count().await.unwrap(), 5);

    // Test mutation
    network.set_peer_count(10);
    assert_eq!(network.peer_count().await.unwrap(), 10);

    network.set_listening(false);
    assert!(!network.is_listening().await.unwrap());
}

/// Test sync status.
#[tokio::test]
async fn test_stub_storage_sync_status() {
    let storage = StubRpcStorage::default();

    let status = storage.sync_status().await.unwrap();
    assert!(matches!(status, SyncStatus::NotSyncing));
    assert!(!status.is_syncing());
}

/// Test block number or tag parsing.
#[test]
fn test_block_number_or_tag() {
    // Number conversion
    let num: BlockNumberOrTag = 42u64.into();
    assert!(matches!(num, BlockNumberOrTag::Number(42)));

    // Default is Latest
    let default = BlockNumberOrTag::default();
    assert!(matches!(default, BlockNumberOrTag::Latest));
}
