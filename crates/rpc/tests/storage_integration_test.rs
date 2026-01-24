//! Integration tests for MdbxRpcStorage.
//!
//! These tests verify that the MDBX-backed RPC storage correctly integrates
//! with the block and receipt stores from cipherbft-storage.

use std::sync::Arc;

use cipherbft_execution::database::InMemoryProvider;
use cipherbft_rpc::{MdbxRpcStorage, RpcStorage, SyncStatus};
use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxBlockStore, MdbxLogStore, MdbxReceiptStore};
use cipherbft_rpc::BlockNumberOrTag;
use cipherbft_storage::receipts::{Log as ReceiptLog, Receipt};
use cipherbft_storage::{BlockStore, LogStore, ReceiptStore, StoredLog};

/// Test chain ID for integration tests.
const TEST_CHAIN_ID: u64 = 85300;

#[tokio::test]
async fn test_mdbx_rpc_storage_struct_creation() {
    // This test verifies that MdbxRpcStorage can be constructed
    // with a provider, block store, and receipt store.

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    // Create the underlying stores
    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));

    // Create an in-memory provider for state queries
    let provider = Arc::new(InMemoryProvider::new());

    // Create MdbxRpcStorage - this is the actual test
    let storage = MdbxRpcStorage::new(provider, block_store.clone(), receipt_store.clone(), TEST_CHAIN_ID);

    // Verify the storage was created correctly
    assert_eq!(storage.chain_id(), TEST_CHAIN_ID);
    assert_eq!(storage.latest_block(), 0);

    // Verify we can access the underlying stores
    assert!(Arc::ptr_eq(storage.block_store(), &block_store));
    assert!(Arc::ptr_eq(storage.receipt_store(), &receipt_store));
}

#[tokio::test]
async fn test_mdbx_rpc_storage_latest_block_accessors() {
    // This test verifies that set_latest_block() and latest_block() work correctly.

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    let storage = MdbxRpcStorage::new(provider, block_store, receipt_store, TEST_CHAIN_ID);

    // Initially latest block should be 0
    assert_eq!(storage.latest_block(), 0);

    // Set latest block to a new value
    storage.set_latest_block(100);
    assert_eq!(storage.latest_block(), 100);

    // Update to a higher value
    storage.set_latest_block(12345);
    assert_eq!(storage.latest_block(), 12345);

    // Can also set to a lower value (e.g., during reorg)
    storage.set_latest_block(12300);
    assert_eq!(storage.latest_block(), 12300);
}

#[tokio::test]
async fn test_mdbx_rpc_storage_thread_safety() {
    // This test verifies that MdbxRpcStorage can be safely shared across threads.

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    let storage = Arc::new(MdbxRpcStorage::new(
        provider,
        block_store,
        receipt_store,
        TEST_CHAIN_ID,
    ));

    // Spawn multiple tasks that update the latest block
    let mut handles = vec![];
    for i in 0..10 {
        let storage_clone = Arc::clone(&storage);
        handles.push(tokio::spawn(async move {
            for j in 0..100 {
                storage_clone.set_latest_block(i * 100 + j);
            }
        }));
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // The final value should be some value that was set
    // (we can't predict which one due to race conditions, but it should be valid)
    let final_block = storage.latest_block();
    assert!(final_block < 1000); // Should be in the range we set
}

#[tokio::test]
async fn test_block_store_operations() {
    // Test basic block store operations

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env));

    // Initially no blocks
    assert!(block_store.get_latest_block_number().await.unwrap().is_none());
    assert!(!block_store.has_block(0).await.unwrap());
    assert!(block_store.get_block_by_number(0).await.unwrap().is_none());
}

#[tokio::test]
async fn test_receipt_store_operations() {
    // Test basic receipt store operations

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let receipt_store = Arc::new(MdbxReceiptStore::new(env));

    // Initially no receipts
    let missing_hash = [0u8; 32];
    assert!(!receipt_store.has_receipt(&missing_hash).await.unwrap());
    assert!(receipt_store.get_receipt(&missing_hash).await.unwrap().is_none());
    assert!(receipt_store.get_receipts_by_block(0).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_shared_database_environment() {
    // Test that block and receipt stores can share the same database environment

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    // Both stores share the same environment
    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));

    // Both should work independently
    assert!(block_store.get_latest_block_number().await.unwrap().is_none());
    assert!(!receipt_store.has_receipt(&[1u8; 32]).await.unwrap());

    // Verify environment is shared - at least 3 strong references
    // (db.env + our clone + block_store + receipt_store = 4 total)
    assert!(Arc::strong_count(&env) >= 3);
}

#[tokio::test]
async fn test_mdbx_rpc_storage_with_stores() {
    // Test that MdbxRpcStorage correctly integrates with underlying stores

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    let storage = MdbxRpcStorage::new(
        provider.clone(),
        block_store.clone(),
        receipt_store.clone(),
        TEST_CHAIN_ID,
    );

    // Access underlying stores through the storage wrapper
    assert!(storage.block_store().get_latest_block_number().await.unwrap().is_none());
    assert!(!storage.receipt_store().has_receipt(&[0u8; 32]).await.unwrap());

    // Provider should also be accessible
    assert!(Arc::ptr_eq(storage.provider(), &provider));
}

#[tokio::test]
async fn test_mdbx_rpc_storage_sync_status() {
    // Test sync status tracking for MdbxRpcStorage

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    let storage = MdbxRpcStorage::new(provider, block_store, receipt_store, TEST_CHAIN_ID);

    // Initially not syncing
    let status = storage.sync_status().await.unwrap();
    assert!(matches!(status, SyncStatus::NotSyncing));

    // Set syncing status
    storage.set_syncing(0, 500, 1000);
    let status = storage.sync_status().await.unwrap();
    match status {
        SyncStatus::Syncing {
            starting_block,
            current_block,
            highest_block,
        } => {
            assert_eq!(starting_block, 0);
            assert_eq!(current_block, 500);
            assert_eq!(highest_block, 1000);
        }
        _ => panic!("Expected Syncing status"),
    }

    // Update sync progress
    storage.set_syncing(0, 750, 1000);
    let status = storage.sync_status().await.unwrap();
    match status {
        SyncStatus::Syncing {
            current_block,
            highest_block,
            ..
        } => {
            assert_eq!(current_block, 750);
            assert_eq!(highest_block, 1000);
        }
        _ => panic!("Expected Syncing status"),
    }

    // Mark as synced
    storage.set_synced();
    let status = storage.sync_status().await.unwrap();
    assert!(matches!(status, SyncStatus::NotSyncing));
}

#[tokio::test]
async fn test_mdbx_rpc_storage_sync_status_thread_safety() {
    // Test that sync status can be updated from multiple threads

    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    let storage = Arc::new(MdbxRpcStorage::new(
        provider,
        block_store,
        receipt_store,
        TEST_CHAIN_ID,
    ));

    // Spawn multiple tasks that update sync status
    let mut handles = Vec::new();
    for i in 0..5 {
        let storage_clone = Arc::clone(&storage);
        handles.push(tokio::spawn(async move {
            for j in 0..20 {
                storage_clone.set_syncing(0, i * 20 + j, 100);
            }
        }));
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Should still be in a valid syncing state
    let status = storage.sync_status().await.unwrap();
    match status {
        SyncStatus::Syncing {
            highest_block, ..
        } => {
            assert_eq!(highest_block, 100);
        }
        _ => panic!("Expected Syncing status"),
    }

    // Mark as synced from one thread
    storage.set_synced();
    let status = storage.sync_status().await.unwrap();
    assert!(matches!(status, SyncStatus::NotSyncing));
}

#[tokio::test]
async fn test_mdbx_rpc_storage_with_log_store() {
    // Test MdbxRpcStorage construction with log store using with_log_store constructor

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    // Create all stores including log store
    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let log_store = Arc::new(MdbxLogStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    // Create MdbxRpcStorage with log store
    let storage = MdbxRpcStorage::with_log_store(
        provider,
        block_store.clone(),
        receipt_store.clone(),
        log_store.clone(),
        TEST_CHAIN_ID,
    );

    // Verify the storage was created correctly
    assert_eq!(storage.chain_id(), TEST_CHAIN_ID);
    assert_eq!(storage.latest_block(), 0);

    // Verify log store is accessible
    let retrieved_log_store = storage.log_store();
    assert!(retrieved_log_store.is_some());
    assert!(Arc::ptr_eq(retrieved_log_store.unwrap(), &log_store));

    // Verify other stores are also accessible
    assert!(Arc::ptr_eq(storage.block_store(), &block_store));
    assert!(Arc::ptr_eq(storage.receipt_store(), &receipt_store));
}

#[tokio::test]
async fn test_mdbx_rpc_storage_without_log_store() {
    // Test that MdbxRpcStorage created without log store returns None for log_store()

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    // Create without log store using new() constructor
    let storage = MdbxRpcStorage::new(provider, block_store, receipt_store, TEST_CHAIN_ID);

    // Verify log store is None
    assert!(storage.log_store().is_none());
}

#[tokio::test]
async fn test_log_store_basic_operations() {
    // Test basic log store operations

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let log_store = Arc::new(MdbxLogStore::new(env));

    // Initially no logs for any block
    let logs = log_store.get_logs_by_block(0).await.unwrap();
    assert!(logs.is_empty());

    // Create a test log
    let test_log = StoredLog {
        address: [0x42; 20],
        topics: vec![[0x11; 32], [0x22; 32]],
        data: vec![0xab, 0xcd, 0xef],
        block_number: 100,
        block_hash: [0xaa; 32],
        transaction_hash: [0xbb; 32],
        transaction_index: 0,
        log_index: 0,
        removed: false,
    };

    // Store the log
    log_store.put_logs(&[test_log.clone()]).await.unwrap();

    // Retrieve by block number
    let logs = log_store.get_logs_by_block(100).await.unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].address, [0x42; 20]);
    assert_eq!(logs[0].block_number, 100);
    assert_eq!(logs[0].topics.len(), 2);
}

#[tokio::test]
async fn test_log_store_multiple_logs_per_block() {
    // Test storing and retrieving multiple logs for the same block

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let log_store = Arc::new(MdbxLogStore::new(env));

    // Create multiple test logs for the same block
    let logs: Vec<StoredLog> = (0..5)
        .map(|i| StoredLog {
            address: [0x42 + i as u8; 20],
            topics: vec![[0x11 + i as u8; 32]],
            data: vec![i as u8],
            block_number: 200,
            block_hash: [0xaa; 32],
            transaction_hash: [0xbb + i as u8; 32],
            transaction_index: i as u32,
            log_index: i as u32,
            removed: false,
        })
        .collect();

    // Store all logs
    log_store.put_logs(&logs).await.unwrap();

    // Retrieve by block number
    let retrieved = log_store.get_logs_by_block(200).await.unwrap();
    assert_eq!(retrieved.len(), 5);

    // Verify logs are in order by log_index
    for (i, log) in retrieved.iter().enumerate() {
        assert_eq!(log.log_index, i as u32);
    }
}

#[tokio::test]
async fn test_log_store_delete_by_block() {
    // Test deleting logs by block number

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let log_store = Arc::new(MdbxLogStore::new(env));

    // Store logs for two different blocks
    let logs_block_1: Vec<StoredLog> = (0..3)
        .map(|i| StoredLog {
            address: [0x42; 20],
            topics: vec![[0x11; 32]],
            data: vec![i as u8],
            block_number: 100,
            block_hash: [0xaa; 32],
            transaction_hash: [0xbb + i as u8; 32],
            transaction_index: i as u32,
            log_index: i as u32,
            removed: false,
        })
        .collect();

    let logs_block_2: Vec<StoredLog> = (0..2)
        .map(|i| StoredLog {
            address: [0x43; 20],
            topics: vec![[0x22; 32]],
            data: vec![i as u8],
            block_number: 101,
            block_hash: [0xbb; 32],
            transaction_hash: [0xcc + i as u8; 32],
            transaction_index: i as u32,
            log_index: i as u32,
            removed: false,
        })
        .collect();

    log_store.put_logs(&logs_block_1).await.unwrap();
    log_store.put_logs(&logs_block_2).await.unwrap();

    // Verify both blocks have logs
    assert_eq!(log_store.get_logs_by_block(100).await.unwrap().len(), 3);
    assert_eq!(log_store.get_logs_by_block(101).await.unwrap().len(), 2);

    // Delete logs for block 100
    log_store.delete_logs_by_block(100).await.unwrap();

    // Verify block 100 has no logs, but block 101 still does
    assert!(log_store.get_logs_by_block(100).await.unwrap().is_empty());
    assert_eq!(log_store.get_logs_by_block(101).await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_mdbx_rpc_storage_get_block_receipts() {
    // Test get_block_receipts method for MdbxRpcStorage

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    let storage = MdbxRpcStorage::new(provider, block_store.clone(), receipt_store.clone(), TEST_CHAIN_ID);

    // Query for non-existent block should return None
    let result = storage.get_block_receipts(BlockNumberOrTag::Number(100)).await.unwrap();
    assert!(result.is_none(), "Non-existent block should return None");

    // Store a block first
    let block = cipherbft_storage::Block {
        number: 100,
        hash: [0xaa; 32],
        parent_hash: [0x00; 32],
        ommers_hash: [0x00; 32],
        beneficiary: [0x01; 20],
        state_root: [0x00; 32],
        transactions_root: [0x00; 32],
        receipts_root: [0x00; 32],
        logs_bloom: vec![0; 256],
        difficulty: [0; 32],
        gas_limit: 30_000_000,
        gas_used: 21_000,
        timestamp: 1700000000,
        extra_data: vec![],
        mix_hash: [0x00; 32],
        nonce: [0; 8],
        base_fee_per_gas: Some(1_000_000_000),
        transaction_hashes: vec![[0x11; 32], [0x22; 32]],
        transaction_count: 2,
        total_difficulty: [0; 32],
    };
    block_store.put_block(&block).await.unwrap();

    // Store receipts for the block
    let receipts = vec![
        Receipt {
            transaction_hash: [0x11; 32],
            block_number: 100,
            block_hash: [0xaa; 32],
            transaction_index: 0,
            from: [0x01; 20],
            to: Some([0x02; 20]),
            contract_address: None,
            gas_used: 21000,
            cumulative_gas_used: 21000,
            status: true,
            logs: vec![],
            logs_bloom: vec![0; 256],
            effective_gas_price: 1_000_000_000,
            transaction_type: 0,
        },
        Receipt {
            transaction_hash: [0x22; 32],
            block_number: 100,
            block_hash: [0xaa; 32],
            transaction_index: 1,
            from: [0x03; 20],
            to: Some([0x04; 20]),
            contract_address: None,
            gas_used: 50000,
            cumulative_gas_used: 71000,
            status: true,
            logs: vec![ReceiptLog {
                address: [0x42; 20],
                topics: vec![[0xab; 32]],
                data: vec![1, 2, 3],
                log_index: 0,
                transaction_index: 1,
            }],
            logs_bloom: vec![0; 256],
            effective_gas_price: 1_000_000_000,
            transaction_type: 2,
        },
    ];
    receipt_store.put_receipts(&receipts).await.unwrap();

    // Query block receipts
    let result = storage.get_block_receipts(BlockNumberOrTag::Number(100)).await.unwrap();
    assert!(result.is_some(), "Block with receipts should return Some");

    let rpc_receipts = result.unwrap();
    assert_eq!(rpc_receipts.len(), 2, "Should return 2 receipts");

    // Verify first receipt
    assert_eq!(rpc_receipts[0].transaction_index, Some(0));
    assert_eq!(rpc_receipts[0].block_number, Some(100));
    assert!(rpc_receipts[0].status());

    // Verify second receipt has logs
    assert_eq!(rpc_receipts[1].transaction_index, Some(1));
    assert_eq!(rpc_receipts[1].inner.logs().len(), 1);
}

#[tokio::test]
async fn test_mdbx_rpc_storage_get_block_receipts_empty_block() {
    // Test get_block_receipts for a block with no transactions

    let temp_dir = tempfile::tempdir().unwrap();
    let config = DatabaseConfig::new(temp_dir.path());
    let db = Database::open(config).unwrap();
    let env = Arc::clone(db.env());

    let block_store = Arc::new(MdbxBlockStore::new(env.clone()));
    let receipt_store = Arc::new(MdbxReceiptStore::new(env.clone()));
    let provider = Arc::new(InMemoryProvider::new());

    let storage = MdbxRpcStorage::new(provider, block_store.clone(), receipt_store, TEST_CHAIN_ID);

    // Store a block with no transactions
    let block = cipherbft_storage::Block {
        number: 50,
        hash: [0xbb; 32],
        parent_hash: [0x00; 32],
        ommers_hash: [0x00; 32],
        beneficiary: [0x01; 20],
        state_root: [0x00; 32],
        transactions_root: [0x00; 32],
        receipts_root: [0x00; 32],
        logs_bloom: vec![0; 256],
        difficulty: [0; 32],
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 1700000000,
        extra_data: vec![],
        mix_hash: [0x00; 32],
        nonce: [0; 8],
        base_fee_per_gas: Some(1_000_000_000),
        transaction_hashes: vec![], // No transactions
        transaction_count: 0,
        total_difficulty: [0; 32],
    };
    block_store.put_block(&block).await.unwrap();

    // Query block receipts for empty block
    let result = storage.get_block_receipts(BlockNumberOrTag::Number(50)).await.unwrap();

    // Block exists but has no receipts - should return Some with empty vec
    assert!(result.is_some(), "Existing block should return Some");
    assert!(result.unwrap().is_empty(), "Empty block should return empty receipts");
}
