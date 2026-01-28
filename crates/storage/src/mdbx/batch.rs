//! MDBX-based implementation of BatchStore.
//!
//! This module provides the [`MdbxBatchStore`] implementation of [`BatchStore`] trait
//! using MDBX as the backing storage engine for worker batch persistence.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use cipherbft_metrics::storage::{
    STORAGE_BATCH_COMMIT, STORAGE_READ_LATENCY, STORAGE_WRITE_LATENCY,
};
use reth_db::Database;
use reth_db_api::transaction::{DbTx, DbTxMut};

use super::database::DatabaseEnv;
use super::tables::{Batches, BincodeValue, HashKey, StoredBatch};
use crate::batch::{BatchStore, BatchStoreResult};
use crate::error::StorageError;
use cipherbft_data_chain::Batch;
use cipherbft_types::Hash;

/// Helper to convert database errors to storage errors.
fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// MDBX-based batch storage implementation.
///
/// This implementation uses reth-db (MDBX) for persistent storage of transaction
/// batches. Batches are stored in the `Batches` table, indexed by their SHA-256
/// content hash.
///
/// # Thread Safety
///
/// This type is thread-safe and can be shared across threads using `Arc`.
/// The underlying MDBX database handles concurrent access.
///
/// # Example
///
/// ```ignore
/// use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxBatchStore};
/// use cipherbft_storage::BatchStore;
/// use std::sync::Arc;
///
/// let config = DatabaseConfig::new("/path/to/db");
/// let db = Arc::new(Database::open(config)?);
/// let store = MdbxBatchStore::new(db.env().clone());
///
/// let batch = Batch::new(0, vec![vec![1, 2, 3]], 12345);
/// store.put_batch(&batch).await?;
/// ```
pub struct MdbxBatchStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxBatchStore {
    /// Create a new MDBX batch store.
    ///
    /// # Arguments
    /// * `db` - Shared reference to the MDBX database environment
    pub fn new(db: Arc<DatabaseEnv>) -> Self {
        Self { db }
    }

    /// Convert a Batch to StoredBatch for persistence.
    fn batch_to_stored(batch: &Batch) -> StoredBatch {
        StoredBatch {
            worker_id: batch.worker_id,
            transactions: batch.transactions.clone(),
            timestamp: batch.timestamp,
        }
    }

    /// Convert a StoredBatch back to a Batch.
    fn stored_to_batch(stored: StoredBatch) -> Batch {
        Batch {
            worker_id: stored.worker_id,
            transactions: stored.transactions,
            timestamp: stored.timestamp,
        }
    }
}

#[async_trait]
impl BatchStore for MdbxBatchStore {
    async fn put_batch(&self, batch: &Batch) -> BatchStoreResult<()> {
        let start = Instant::now();
        let hash = batch.hash();
        let stored = Self::batch_to_stored(batch);
        let key = HashKey::from_slice(hash.as_bytes());

        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;
        tx.put::<Batches>(key, BincodeValue(stored))
            .map_err(|e| db_err(e.to_string()))?;

        let commit_start = Instant::now();
        tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["batches"])
            .observe(start.elapsed().as_secs_f64());

        Ok(())
    }

    async fn get_batch(&self, digest: &Hash) -> BatchStoreResult<Option<Batch>> {
        let start = Instant::now();
        let key = HashKey::from_slice(digest.as_bytes());

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = tx.get::<Batches>(key).map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["batches"])
            .observe(start.elapsed().as_secs_f64());

        match result {
            Some(bincode_value) => {
                let batch = Self::stored_to_batch(bincode_value.0);
                Ok(Some(batch))
            }
            None => Ok(None),
        }
    }

    async fn has_batch(&self, digest: &Hash) -> BatchStoreResult<bool> {
        let start = Instant::now();
        let key = HashKey::from_slice(digest.as_bytes());

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = tx.get::<Batches>(key).map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["batches"])
            .observe(start.elapsed().as_secs_f64());

        Ok(result.is_some())
    }

    async fn delete_batch(&self, digest: &Hash) -> BatchStoreResult<()> {
        let start = Instant::now();
        let key = HashKey::from_slice(digest.as_bytes());

        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;
        tx.delete::<Batches>(key, None)
            .map_err(|e| db_err(e.to_string()))?;

        let commit_start = Instant::now();
        tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["batches"])
            .observe(start.elapsed().as_secs_f64());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdbx::Database;

    fn create_test_db() -> (Arc<DatabaseEnv>, tempfile::TempDir) {
        let (db, temp_dir) = Database::open_temp().unwrap();
        (Arc::clone(db.env()), temp_dir)
    }

    #[tokio::test]
    async fn test_batch_roundtrip() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBatchStore::new(db);

        let batch = Batch::new(0, vec![vec![1, 2, 3], vec![4, 5, 6]], 12345);
        let hash = batch.hash();

        // Store
        store.put_batch(&batch).await.unwrap();

        // Retrieve
        let retrieved = store.get_batch(&hash).await.unwrap().unwrap();
        assert_eq!(retrieved.worker_id, batch.worker_id);
        assert_eq!(retrieved.transactions, batch.transactions);
        assert_eq!(retrieved.timestamp, batch.timestamp);
    }

    #[tokio::test]
    async fn test_batch_has() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBatchStore::new(db);

        let batch = Batch::new(1, vec![vec![7, 8, 9]], 99999);
        let hash = batch.hash();

        assert!(!store.has_batch(&hash).await.unwrap());
        store.put_batch(&batch).await.unwrap();
        assert!(store.has_batch(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_batch_delete() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBatchStore::new(db);

        let batch = Batch::new(2, vec![vec![10, 11]], 11111);
        let hash = batch.hash();

        store.put_batch(&batch).await.unwrap();
        assert!(store.has_batch(&hash).await.unwrap());

        store.delete_batch(&hash).await.unwrap();
        assert!(!store.has_batch(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_batch_not_found() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBatchStore::new(db);

        let missing_hash = Hash::from_bytes([0u8; 32]);
        let result = store.get_batch(&missing_hash).await.unwrap();
        assert!(result.is_none());
    }
}
