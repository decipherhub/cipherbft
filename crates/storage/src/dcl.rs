//! DclStore trait definition per ADR-010
//!
//! This module defines the [`DclStore`] trait which provides storage operations
//! for the Data Chain Layer (DCL). The trait is designed to be implemented by
//! different backends (in-memory, RocksDB, MDBX, etc.).
//!
//! # Operations
//!
//! The trait provides CRUD operations for:
//! - **Batches**: Transaction batches created by Workers
//! - **Cars**: Certified Available Records created by Primaries
//! - **Attestations**: Aggregated BLS attestations for Cars
//! - **Cuts**: Both pending and finalized Cuts for consensus
//!
//! # Transaction Support
//!
//! The trait supports batch operations through the [`DclStoreTx`] trait,
//! allowing multiple operations to be executed atomically.

use crate::error::Result;
use crate::tables::{CarRange, CutRange};
use async_trait::async_trait;
use cipherbft_data_chain::{AggregatedAttestation, Batch, Car, Cut};
use cipherbft_types::{Hash, ValidatorId};

/// DCL storage trait for persistent data management
///
/// This trait provides async storage operations for all DCL data types.
/// Implementations must be thread-safe (Send + Sync).
#[async_trait]
pub trait DclStore: Send + Sync {
    // ============================================================
    // Batch Operations (T051)
    // ============================================================

    /// Store a batch
    ///
    /// # Arguments
    /// * `batch` - The batch to store
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(StorageError::DuplicateEntry)` if batch already exists
    async fn put_batch(&self, batch: Batch) -> Result<()>;

    /// Get a batch by its digest hash
    ///
    /// # Arguments
    /// * `hash` - Hash of the batch
    ///
    /// # Returns
    /// * `Ok(Some(batch))` if found
    /// * `Ok(None)` if not found
    async fn get_batch(&self, hash: &Hash) -> Result<Option<Batch>>;

    /// Check if a batch exists
    ///
    /// # Arguments
    /// * `hash` - Hash of the batch
    async fn has_batch(&self, hash: &Hash) -> Result<bool>;

    /// Delete a batch
    ///
    /// # Arguments
    /// * `hash` - Hash of the batch to delete
    ///
    /// # Returns
    /// * `Ok(true)` if deleted
    /// * `Ok(false)` if not found
    async fn delete_batch(&self, hash: &Hash) -> Result<bool>;

    // ============================================================
    // Car Operations (T052)
    // ============================================================

    /// Store a Car
    ///
    /// # Arguments
    /// * `car` - The Car to store
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(StorageError::DuplicateEntry)` if Car already exists at this position
    async fn put_car(&self, car: Car) -> Result<()>;

    /// Get a Car by validator and position
    ///
    /// # Arguments
    /// * `validator` - Validator ID
    /// * `position` - Position in the validator's lane
    ///
    /// # Returns
    /// * `Ok(Some(car))` if found
    /// * `Ok(None)` if not found
    async fn get_car(&self, validator: &ValidatorId, position: u64) -> Result<Option<Car>>;

    /// Get a Car by its hash
    ///
    /// # Arguments
    /// * `hash` - Hash of the Car
    ///
    /// # Returns
    /// * `Ok(Some(car))` if found
    /// * `Ok(None)` if not found
    async fn get_car_by_hash(&self, hash: &Hash) -> Result<Option<Car>>;

    /// Get the highest position for a validator
    ///
    /// # Arguments
    /// * `validator` - Validator ID
    ///
    /// # Returns
    /// * `Ok(Some(position))` if validator has Cars
    /// * `Ok(None)` if validator has no Cars
    async fn get_highest_car_position(&self, validator: &ValidatorId) -> Result<Option<u64>>;

    /// Get Cars in a range for a validator
    ///
    /// # Arguments
    /// * `range` - The range of Cars to retrieve
    ///
    /// # Returns
    /// Vector of Cars in the range, ordered by position
    async fn get_cars_range(&self, range: CarRange) -> Result<Vec<Car>>;

    /// Check if a Car exists
    ///
    /// # Arguments
    /// * `validator` - Validator ID
    /// * `position` - Position in the validator's lane
    async fn has_car(&self, validator: &ValidatorId, position: u64) -> Result<bool>;

    /// Delete a Car
    ///
    /// # Arguments
    /// * `validator` - Validator ID
    /// * `position` - Position in the validator's lane
    ///
    /// # Returns
    /// * `Ok(true)` if deleted
    /// * `Ok(false)` if not found
    async fn delete_car(&self, validator: &ValidatorId, position: u64) -> Result<bool>;

    // ============================================================
    // Attestation Operations (T053)
    // ============================================================

    /// Store an aggregated attestation
    ///
    /// # Arguments
    /// * `attestation` - The aggregated attestation to store
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * Note: This overwrites existing attestations for the same Car
    async fn put_attestation(&self, attestation: AggregatedAttestation) -> Result<()>;

    /// Get an aggregated attestation by Car hash
    ///
    /// # Arguments
    /// * `car_hash` - Hash of the Car
    ///
    /// # Returns
    /// * `Ok(Some(attestation))` if found
    /// * `Ok(None)` if not found
    async fn get_attestation(&self, car_hash: &Hash) -> Result<Option<AggregatedAttestation>>;

    /// Check if an attestation exists
    ///
    /// # Arguments
    /// * `car_hash` - Hash of the Car
    async fn has_attestation(&self, car_hash: &Hash) -> Result<bool>;

    /// Delete an attestation
    ///
    /// # Arguments
    /// * `car_hash` - Hash of the Car
    ///
    /// # Returns
    /// * `Ok(true)` if deleted
    /// * `Ok(false)` if not found
    async fn delete_attestation(&self, car_hash: &Hash) -> Result<bool>;

    // ============================================================
    // Cut Operations (T054)
    // ============================================================

    /// Store a pending Cut
    ///
    /// # Arguments
    /// * `cut` - The Cut to store as pending
    async fn put_pending_cut(&self, cut: Cut) -> Result<()>;

    /// Get a pending Cut by height
    ///
    /// # Arguments
    /// * `height` - Consensus height
    async fn get_pending_cut(&self, height: u64) -> Result<Option<Cut>>;

    /// Get all pending Cuts
    async fn get_all_pending_cuts(&self) -> Result<Vec<Cut>>;

    /// Move a pending Cut to finalized
    ///
    /// # Arguments
    /// * `height` - Consensus height
    ///
    /// # Returns
    /// * `Ok(Some(cut))` if the Cut was finalized
    /// * `Ok(None)` if no pending Cut at this height
    async fn finalize_cut(&self, height: u64) -> Result<Option<Cut>>;

    /// Delete a pending Cut
    ///
    /// # Arguments
    /// * `height` - Consensus height
    ///
    /// # Returns
    /// * `Ok(true)` if deleted
    /// * `Ok(false)` if not found
    async fn delete_pending_cut(&self, height: u64) -> Result<bool>;

    /// Store a finalized Cut directly
    ///
    /// # Arguments
    /// * `cut` - The Cut to store as finalized
    async fn put_finalized_cut(&self, cut: Cut) -> Result<()>;

    /// Get a finalized Cut by height
    ///
    /// # Arguments
    /// * `height` - Consensus height
    async fn get_finalized_cut(&self, height: u64) -> Result<Option<Cut>>;

    /// Get the latest finalized Cut
    async fn get_latest_finalized_cut(&self) -> Result<Option<Cut>>;

    /// Get finalized Cuts in a range
    ///
    /// # Arguments
    /// * `range` - The range of heights to retrieve
    ///
    /// # Returns
    /// Vector of Cuts in the range, ordered by height
    async fn get_finalized_cuts_range(&self, range: CutRange) -> Result<Vec<Cut>>;

    // ============================================================
    // Garbage Collection (T055)
    // ============================================================

    /// Prune data older than a given height
    ///
    /// This removes:
    /// - Finalized Cuts older than the height
    /// - Cars that are not referenced by retained Cuts
    /// - Attestations for pruned Cars
    /// - Batches for pruned Cars
    ///
    /// # Arguments
    /// * `height` - Prune data before this height
    ///
    /// # Returns
    /// Number of entries pruned
    async fn prune_before(&self, height: u64) -> Result<u64>;

    /// Get storage statistics
    async fn stats(&self) -> Result<StorageStats>;
}

/// Storage statistics
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Number of batches stored
    pub batch_count: u64,
    /// Number of Cars stored
    pub car_count: u64,
    /// Number of attestations stored
    pub attestation_count: u64,
    /// Number of pending Cuts
    pub pending_cut_count: u64,
    /// Number of finalized Cuts
    pub finalized_cut_count: u64,
    /// Estimated storage size in bytes
    pub storage_bytes: u64,
}

/// Batch transaction interface for atomic operations
///
/// This trait allows multiple storage operations to be batched together
/// and executed atomically.
#[async_trait]
pub trait DclStoreTx: Send + Sync {
    /// Commit the transaction
    async fn commit(self) -> Result<()>;

    /// Abort the transaction
    async fn abort(self) -> Result<()>;

    /// Put a batch in this transaction
    async fn put_batch(&mut self, batch: Batch) -> Result<()>;

    /// Put a Car in this transaction
    async fn put_car(&mut self, car: Car) -> Result<()>;

    /// Put an attestation in this transaction
    async fn put_attestation(&mut self, attestation: AggregatedAttestation) -> Result<()>;

    /// Put a pending Cut in this transaction
    async fn put_pending_cut(&mut self, cut: Cut) -> Result<()>;

    /// Finalize a Cut in this transaction
    async fn finalize_cut(&mut self, height: u64) -> Result<Option<Cut>>;
}

/// Extension trait for stores that support transactions
#[async_trait]
pub trait DclStoreExt: DclStore {
    /// Transaction type for this store
    type Transaction: DclStoreTx;

    /// Begin a new transaction
    async fn begin_tx(&self) -> Result<Self::Transaction>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_stats_default() {
        let stats = StorageStats::default();
        assert_eq!(stats.batch_count, 0);
        assert_eq!(stats.car_count, 0);
        assert_eq!(stats.attestation_count, 0);
        assert_eq!(stats.pending_cut_count, 0);
        assert_eq!(stats.finalized_cut_count, 0);
        assert_eq!(stats.storage_bytes, 0);
    }
}
