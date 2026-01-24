//! Integration tests for MdbxRpcStorage.
//!
//! These tests verify that the MDBX-backed RPC storage correctly integrates
//! with the block and receipt stores from cipherbft-storage.

use std::sync::Arc;

use cipherbft_execution::database::InMemoryProvider;
use cipherbft_rpc::MdbxRpcStorage;
use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxBlockStore, MdbxReceiptStore};
use cipherbft_storage::{BlockStore, ReceiptStore};

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
