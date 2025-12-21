//! Storage traits for DCL components
//!
//! These traits define the storage interface that can be implemented by
//! different backends (in-memory, RocksDB, MDBX, etc.).
//!
//! The traits are designed to be minimal and focused on DCL needs:
//! - [`BatchStore`]: Storage for transaction batches (Worker)
//! - [`CarStore`]: Storage for Cars (Primary)
//! - [`CutStore`]: Storage for Cuts (Primary/Consensus)

use crate::attestation::AggregatedAttestation;
use crate::batch::Batch;
use crate::car::Car;
use crate::cut::Cut;
use crate::error::DclError;
use async_trait::async_trait;
use cipherbft_types::{Hash, ValidatorId};

/// Batch storage trait for Workers
///
/// This trait provides async storage operations for transaction batches.
#[async_trait]
pub trait BatchStore: Send + Sync {
    /// Store a batch
    ///
    /// # Arguments
    /// * `batch` - The batch to store
    ///
    /// # Returns
    /// The hash of the stored batch
    async fn put_batch(&self, batch: Batch) -> Result<Hash, DclError>;

    /// Get a batch by its hash
    ///
    /// # Arguments
    /// * `hash` - Hash of the batch
    ///
    /// # Returns
    /// * `Ok(Some(batch))` if found
    /// * `Ok(None)` if not found
    async fn get_batch(&self, hash: &Hash) -> Result<Option<Batch>, DclError>;

    /// Check if a batch exists
    ///
    /// # Arguments
    /// * `hash` - Hash of the batch
    async fn has_batch(&self, hash: &Hash) -> Result<bool, DclError>;

    /// Get multiple batches by their hashes
    ///
    /// # Arguments
    /// * `hashes` - Hashes of the batches to retrieve
    ///
    /// # Returns
    /// Vector of (hash, Option<batch>) pairs
    async fn get_batches(&self, hashes: &[Hash]) -> Result<Vec<(Hash, Option<Batch>)>, DclError> {
        let mut results = Vec::with_capacity(hashes.len());
        for hash in hashes {
            let batch = self.get_batch(hash).await?;
            results.push((*hash, batch));
        }
        Ok(results)
    }

    /// Check which batches are missing
    ///
    /// # Arguments
    /// * `hashes` - Hashes to check
    ///
    /// # Returns
    /// Vector of missing batch hashes
    async fn get_missing_batches(&self, hashes: &[Hash]) -> Result<Vec<Hash>, DclError> {
        let mut missing = Vec::new();
        for hash in hashes {
            if !self.has_batch(hash).await? {
                missing.push(*hash);
            }
        }
        Ok(missing)
    }
}

/// Car storage trait for Primary
///
/// This trait provides storage operations for Cars.
#[async_trait]
pub trait CarStore: Send + Sync {
    /// Store a Car
    ///
    /// # Arguments
    /// * `car` - The Car to store
    async fn put_car(&self, car: Car) -> Result<(), DclError>;

    /// Get a Car by validator and position
    ///
    /// # Arguments
    /// * `validator` - Validator ID
    /// * `position` - Position in the validator's lane
    async fn get_car(
        &self,
        validator: &ValidatorId,
        position: u64,
    ) -> Result<Option<Car>, DclError>;

    /// Get a Car by its hash
    async fn get_car_by_hash(&self, hash: &Hash) -> Result<Option<Car>, DclError>;

    /// Get the highest position for a validator
    async fn get_highest_position(&self, validator: &ValidatorId) -> Result<Option<u64>, DclError>;

    /// Store an aggregated attestation for a Car
    async fn put_attestation(&self, attestation: AggregatedAttestation) -> Result<(), DclError>;

    /// Get an attestation by Car hash
    async fn get_attestation(
        &self,
        car_hash: &Hash,
    ) -> Result<Option<AggregatedAttestation>, DclError>;
}

/// Cut storage trait for Primary/Consensus
///
/// This trait provides storage operations for Cuts.
#[async_trait]
pub trait CutStore: Send + Sync {
    /// Store a pending Cut (awaiting consensus)
    async fn put_pending_cut(&self, cut: Cut) -> Result<(), DclError>;

    /// Get a pending Cut by height
    async fn get_pending_cut(&self, height: u64) -> Result<Option<Cut>, DclError>;

    /// Finalize a Cut (move from pending to finalized)
    async fn finalize_cut(&self, height: u64) -> Result<Option<Cut>, DclError>;

    /// Store a finalized Cut directly
    async fn put_finalized_cut(&self, cut: Cut) -> Result<(), DclError>;

    /// Get a finalized Cut by height
    async fn get_finalized_cut(&self, height: u64) -> Result<Option<Cut>, DclError>;

    /// Get the latest finalized Cut
    async fn get_latest_finalized_cut(&self) -> Result<Option<Cut>, DclError>;
}

/// Combined DCL storage trait
///
/// This trait combines all storage operations needed by DCL components.
pub trait DclStorage: BatchStore + CarStore + CutStore {}

// Blanket implementation
impl<T: BatchStore + CarStore + CutStore> DclStorage for T {}
