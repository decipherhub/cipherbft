//! Batch storage trait for persisting worker transaction batches.
//!
//! This module provides the [`BatchStore`] trait for storing and retrieving
//! transaction batches created by DCL Workers. The execution layer uses this
//! interface to retrieve batches when processing finalized Cuts.
//!
//! # Usage
//!
//! ```ignore
//! use cipherbft_storage::BatchStore;
//! use cipherbft_storage::mdbx::MdbxBatchStore;
//!
//! let store = MdbxBatchStore::new(db);
//! store.put_batch(&batch).await?;
//! let retrieved = store.get_batch(&batch.digest().digest).await?;
//! ```

use async_trait::async_trait;
use cipherbft_data_chain::Batch;
use cipherbft_types::Hash;

use crate::error::StorageError;

/// Result type for batch storage operations.
pub type BatchStoreResult<T> = Result<T, StorageError>;

/// Trait for storing and retrieving transaction batches.
///
/// This trait provides async storage operations for transaction batches
/// created by DCL Workers. Batches are indexed by their content hash
/// (SHA-256 digest).
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access from multiple workers and the execution layer.
#[async_trait]
pub trait BatchStore: Send + Sync {
    /// Store a batch.
    ///
    /// The batch is stored using its content hash as the key.
    /// If a batch with the same hash already exists, it is overwritten.
    ///
    /// # Arguments
    /// * `batch` - The batch to store
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn put_batch(&self, batch: &Batch) -> BatchStoreResult<()>;

    /// Retrieve a batch by its digest hash.
    ///
    /// # Arguments
    /// * `digest` - SHA-256 hash of the batch contents
    ///
    /// # Returns
    /// * `Ok(Some(batch))` if the batch exists
    /// * `Ok(None)` if the batch does not exist
    /// * `Err(...)` if the storage operation fails
    async fn get_batch(&self, digest: &Hash) -> BatchStoreResult<Option<Batch>>;

    /// Check if a batch exists.
    ///
    /// This is a lightweight operation that does not deserialize the batch.
    ///
    /// # Arguments
    /// * `digest` - SHA-256 hash of the batch contents
    ///
    /// # Returns
    /// * `Ok(true)` if the batch exists
    /// * `Ok(false)` if the batch does not exist
    /// * `Err(...)` if the storage operation fails
    async fn has_batch(&self, digest: &Hash) -> BatchStoreResult<bool>;

    /// Delete a batch (for pruning).
    ///
    /// Removes the batch with the given hash from storage.
    /// This is typically used during garbage collection/pruning.
    ///
    /// # Arguments
    /// * `digest` - SHA-256 hash of the batch to delete
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    /// Does not return an error if the batch does not exist.
    async fn delete_batch(&self, digest: &Hash) -> BatchStoreResult<()>;
}
