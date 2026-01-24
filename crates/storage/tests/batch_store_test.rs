//! Integration tests for BatchStore trait and MdbxBatchStore implementation
//!
//! These tests verify that the MDBX-backed batch storage correctly implements
//! the BatchStore trait for worker batch persistence.

#![cfg(feature = "mdbx")]

use cipherbft_data_chain::Batch;
use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxBatchStore};
use cipherbft_storage::BatchStore;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_batch_store_put_get() {
    let dir = tempdir().unwrap();
    let config = DatabaseConfig::new(dir.path());
    let db = Database::open(config).unwrap();
    let store = MdbxBatchStore::new(Arc::clone(db.env()));

    // Create a batch
    let batch = Batch::new(0, vec![vec![1, 2, 3], vec![4, 5, 6]], 12345);
    let digest = batch.digest();

    // Store it
    store.put_batch(&batch).await.unwrap();

    // Retrieve it
    let retrieved = store.get_batch(&digest.digest).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.transactions.len(), 2);
    assert_eq!(retrieved.worker_id, 0);
    assert_eq!(retrieved.timestamp, 12345);
}

#[tokio::test]
async fn test_batch_store_get_missing() {
    let dir = tempdir().unwrap();
    let config = DatabaseConfig::new(dir.path());
    let db = Database::open(config).unwrap();
    let store = MdbxBatchStore::new(Arc::clone(db.env()));

    let missing = store.get_batch(&[0u8; 32].into()).await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn test_batch_store_has_batch() {
    let dir = tempdir().unwrap();
    let config = DatabaseConfig::new(dir.path());
    let db = Database::open(config).unwrap();
    let store = MdbxBatchStore::new(Arc::clone(db.env()));

    let batch = Batch::new(1, vec![vec![7, 8, 9]], 54321);
    let digest = batch.digest();

    // Before storing
    assert!(!store.has_batch(&digest.digest).await.unwrap());

    // After storing
    store.put_batch(&batch).await.unwrap();
    assert!(store.has_batch(&digest.digest).await.unwrap());
}

#[tokio::test]
async fn test_batch_store_delete_batch() {
    let dir = tempdir().unwrap();
    let config = DatabaseConfig::new(dir.path());
    let db = Database::open(config).unwrap();
    let store = MdbxBatchStore::new(Arc::clone(db.env()));

    let batch = Batch::new(2, vec![vec![10, 11, 12]], 99999);
    let digest = batch.digest();

    // Store and verify
    store.put_batch(&batch).await.unwrap();
    assert!(store.has_batch(&digest.digest).await.unwrap());

    // Delete
    store.delete_batch(&digest.digest).await.unwrap();

    // Verify deleted
    assert!(!store.has_batch(&digest.digest).await.unwrap());
    assert!(store.get_batch(&digest.digest).await.unwrap().is_none());
}

#[tokio::test]
async fn test_batch_store_multiple_batches() {
    let dir = tempdir().unwrap();
    let config = DatabaseConfig::new(dir.path());
    let db = Database::open(config).unwrap();
    let store = MdbxBatchStore::new(Arc::clone(db.env()));

    // Create multiple batches from different workers
    let batch1 = Batch::new(0, vec![vec![1]], 1000);
    let batch2 = Batch::new(1, vec![vec![2]], 2000);
    let batch3 = Batch::new(2, vec![vec![3]], 3000);

    let digest1 = batch1.digest();
    let digest2 = batch2.digest();
    let digest3 = batch3.digest();

    // Store all
    store.put_batch(&batch1).await.unwrap();
    store.put_batch(&batch2).await.unwrap();
    store.put_batch(&batch3).await.unwrap();

    // Verify all exist and have correct data
    let r1 = store.get_batch(&digest1.digest).await.unwrap().unwrap();
    let r2 = store.get_batch(&digest2.digest).await.unwrap().unwrap();
    let r3 = store.get_batch(&digest3.digest).await.unwrap().unwrap();

    assert_eq!(r1.worker_id, 0);
    assert_eq!(r2.worker_id, 1);
    assert_eq!(r3.worker_id, 2);
}
