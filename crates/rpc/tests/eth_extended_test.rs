//! Integration tests for extended Ethereum RPC methods.
//!
//! Tests the additional eth_* methods including block transaction counts,
//! transaction by index queries, fee estimation, and node status methods.

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256, U64};
use cipherbft_rpc::{
    EthRpcServer, RpcConfig, StubExecutionApi, StubMempoolApi, StubRpcStorage,
};
use jsonrpsee::core::RpcResult;

/// Create a test EthApi instance.
fn create_test_api() -> impl EthRpcServer {
    let storage = Arc::new(StubRpcStorage::default());
    let mempool = Arc::new(StubMempoolApi::new());
    let executor = Arc::new(StubExecutionApi::new());
    let config = Arc::new(RpcConfig::with_chain_id(85300));

    cipherbft_rpc::eth::EthApi::new(storage, mempool, executor, config)
}

// ===== eth_getBlockTransactionCountByHash tests =====

#[tokio::test]
async fn test_get_block_transaction_count_by_hash_not_found() {
    let api = create_test_api();

    // Query for a block that doesn't exist
    let result: RpcResult<Option<U64>> = api
        .get_block_transaction_count_by_hash(B256::ZERO)
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none(), "Non-existent block should return None");
}

#[tokio::test]
async fn test_get_block_transaction_count_by_hash_exists() {
    let api = create_test_api();

    // StubRpcStorage has a block at number 100
    // First get the block hash
    let block = api.get_block_by_number("100".to_string(), false).await.unwrap();
    if let Some(block) = block {
        let hash = block.header.hash;
        let result = api.get_block_transaction_count_by_hash(hash).await.unwrap();

        assert!(result.is_some());
        // Stub returns 2 transaction hashes
        assert_eq!(result.unwrap(), U64::from(2));
    }
}

// ===== eth_getBlockTransactionCountByNumber tests =====

#[tokio::test]
async fn test_get_block_transaction_count_by_number_latest() {
    let api = create_test_api();

    let result: RpcResult<Option<U64>> = api
        .get_block_transaction_count_by_number("latest".to_string())
        .await;

    assert!(result.is_ok());
    // StubRpcStorage returns a block with 2 transactions
    if let Some(count) = result.unwrap() {
        assert_eq!(count, U64::from(2));
    }
}

#[tokio::test]
async fn test_get_block_transaction_count_by_number_specific() {
    let api = create_test_api();

    let result: RpcResult<Option<U64>> = api
        .get_block_transaction_count_by_number("100".to_string())
        .await;

    assert!(result.is_ok());
    if let Some(count) = result.unwrap() {
        assert_eq!(count, U64::from(2));
    }
}

#[tokio::test]
async fn test_get_block_transaction_count_by_number_earliest() {
    let api = create_test_api();

    let result: RpcResult<Option<U64>> = api
        .get_block_transaction_count_by_number("earliest".to_string())
        .await;

    assert!(result.is_ok());
    // Earliest block (0) may not exist in stub, so accept either None or Some
}

// ===== eth_getTransactionByBlockHashAndIndex tests =====

#[tokio::test]
async fn test_get_transaction_by_block_hash_and_index_not_found() {
    let api = create_test_api();

    // Query for a block that doesn't exist
    let result = api
        .get_transaction_by_block_hash_and_index(B256::ZERO, U64::from(0))
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_transaction_by_block_hash_and_index_out_of_bounds() {
    let api = create_test_api();

    // Get a valid block hash
    let block = api.get_block_by_number("100".to_string(), false).await.unwrap();
    if let Some(block) = block {
        let hash = block.header.hash;

        // Request index beyond transaction count
        let result = api
            .get_transaction_by_block_hash_and_index(hash, U64::from(999))
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "Out of bounds index should return None");
    }
}

// ===== eth_getTransactionByBlockNumberAndIndex tests =====

#[tokio::test]
async fn test_get_transaction_by_block_number_and_index_latest() {
    let api = create_test_api();

    // Request first transaction from latest block
    let result = api
        .get_transaction_by_block_number_and_index("latest".to_string(), U64::from(0))
        .await;

    // Should succeed (may return None if no transactions or stub doesn't support full tx)
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_transaction_by_block_number_and_index_out_of_bounds() {
    let api = create_test_api();

    // Request index beyond transaction count
    let result = api
        .get_transaction_by_block_number_and_index("100".to_string(), U64::from(999))
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none(), "Out of bounds index should return None");
}

// ===== eth_maxPriorityFeePerGas tests =====

#[tokio::test]
async fn test_max_priority_fee_per_gas() {
    let api = create_test_api();

    let result: RpcResult<U256> = api.max_priority_fee_per_gas().await;

    assert!(result.is_ok());
    let fee = result.unwrap();

    // Default is 1 gwei (1_000_000_000 wei)
    assert_eq!(fee, U256::from(1_000_000_000_u64));
}

#[tokio::test]
async fn test_max_priority_fee_per_gas_positive() {
    let api = create_test_api();

    let fee = api.max_priority_fee_per_gas().await.unwrap();

    // Should always be positive for EIP-1559 compatibility
    assert!(fee > U256::ZERO, "Priority fee should be positive");
}

// ===== eth_accounts tests =====

#[tokio::test]
async fn test_accounts_empty() {
    let api = create_test_api();

    let result: RpcResult<Vec<Address>> = api.accounts().await;

    assert!(result.is_ok());
    // Default implementation returns empty list (external signing expected)
    assert!(result.unwrap().is_empty());
}

// ===== eth_coinbase tests =====

#[tokio::test]
async fn test_coinbase_zero_address() {
    let api = create_test_api();

    let result: RpcResult<Address> = api.coinbase().await;

    assert!(result.is_ok());
    // Default implementation returns zero address (no validator configured)
    assert_eq!(result.unwrap(), Address::ZERO);
}

// ===== eth_mining tests =====

#[tokio::test]
async fn test_mining_always_false() {
    let api = create_test_api();

    let result: RpcResult<bool> = api.mining().await;

    assert!(result.is_ok());
    // PoS chain never "mining"
    assert!(!result.unwrap());
}

// ===== eth_hashrate tests =====

#[tokio::test]
async fn test_hashrate_always_zero() {
    let api = create_test_api();

    let result: RpcResult<U256> = api.hashrate().await;

    assert!(result.is_ok());
    // PoS chain has no hashrate
    assert_eq!(result.unwrap(), U256::ZERO);
}

// ===== Combined tests =====

#[tokio::test]
async fn test_node_status_consistency() {
    let api = create_test_api();

    // All node status methods should succeed and return consistent PoS values
    let accounts = api.accounts().await.unwrap();
    let coinbase = api.coinbase().await.unwrap();
    let mining = api.mining().await.unwrap();
    let hashrate = api.hashrate().await.unwrap();

    // PoS node characteristics
    assert!(accounts.is_empty(), "No local accounts by default");
    assert_eq!(coinbase, Address::ZERO, "No validator configured");
    assert!(!mining, "PoS nodes don't mine");
    assert_eq!(hashrate, U256::ZERO, "PoS nodes have no hashrate");
}

#[tokio::test]
async fn test_fee_methods_consistency() {
    let api = create_test_api();

    // Both fee methods should return reasonable values
    let gas_price = api.gas_price().await.unwrap();
    let priority_fee = api.max_priority_fee_per_gas().await.unwrap();

    // Priority fee should be less than or equal to gas price (generally)
    // For our stubs, gas_price is 1 gwei and priority_fee is also 1 gwei
    assert!(priority_fee <= gas_price, "Priority fee should not exceed gas price");
}

#[tokio::test]
async fn test_block_transaction_count_consistency() {
    let api = create_test_api();

    // Get block by number and by hash should return same transaction count
    let block = api.get_block_by_number("100".to_string(), false).await.unwrap();

    if let Some(block) = block {
        let hash = block.header.hash;
        let tx_count = block.transactions.len();

        let count_by_hash = api.get_block_transaction_count_by_hash(hash).await.unwrap();
        let count_by_number = api.get_block_transaction_count_by_number("100".to_string()).await.unwrap();

        if let (Some(by_hash), Some(by_number)) = (count_by_hash, count_by_number) {
            assert_eq!(by_hash.to::<usize>(), tx_count);
            assert_eq!(by_number.to::<usize>(), tx_count);
            assert_eq!(by_hash, by_number);
        }
    }
}

// ===== eth_getBlockReceipts tests =====

#[tokio::test]
async fn test_get_block_receipts_not_found() {
    let api = create_test_api();

    // Query for a block that doesn't exist (StubRpcStorage returns None)
    let result = api.get_block_receipts("999999".to_string()).await;

    assert!(result.is_ok());
    // StubRpcStorage returns None for all block receipts queries
    assert!(result.unwrap().is_none(), "Non-existent block should return None");
}

#[tokio::test]
async fn test_get_block_receipts_latest() {
    let api = create_test_api();

    // Query using "latest" tag
    let result = api.get_block_receipts("latest".to_string()).await;

    assert!(result.is_ok());
    // StubRpcStorage returns None for block receipts
    // In a real implementation with receipts, this would return Some(Vec<TransactionReceipt>)
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_block_receipts_earliest() {
    let api = create_test_api();

    // Query genesis block
    let result = api.get_block_receipts("earliest".to_string()).await;

    assert!(result.is_ok());
    // StubRpcStorage returns None
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_block_receipts_pending() {
    let api = create_test_api();

    // Query pending block (treated same as latest)
    let result = api.get_block_receipts("pending".to_string()).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_block_receipts_by_number() {
    let api = create_test_api();

    // Query specific block number
    let result = api.get_block_receipts("100".to_string()).await;

    assert!(result.is_ok());
    // StubRpcStorage returns None
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_block_receipts_hex_number() {
    let api = create_test_api();

    // Query using hex block number (0x64 = 100)
    let result = api.get_block_receipts("0x64".to_string()).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}
