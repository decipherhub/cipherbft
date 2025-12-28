//! MDBX implementation of DclStore
//!
//! This module provides a persistent implementation of the [`DclStore`] trait
//! using MDBX as the storage backend.

use crate::dcl::{DclStore, StorageStats};
use crate::error::{Result, StorageError};
use crate::tables::{CarRange, CutRange};
use async_trait::async_trait;
use cipherbft_data_chain::{AggregatedAttestation, Batch, BatchDigest, Car, Cut};
use cipherbft_types::{Hash, ValidatorId};
use std::sync::Arc;
use tracing::{debug, trace};

use super::database::Database;
use super::tables::{
    BincodeValue, CarTableKey, HashKey, StoredAggregatedAttestation, StoredBatch,
    StoredBatchDigest, StoredCar, StoredCut,
};

/// MDBX-backed DCL store
///
/// Provides persistent storage for all DCL data types using MDBX.
/// Thread-safe and suitable for concurrent access.
pub struct MdbxDclStore {
    /// The underlying database
    db: Arc<Database>,
}

impl MdbxDclStore {
    /// Create a new MDBX DCL store
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Get the underlying database
    pub fn db(&self) -> &Arc<Database> {
        &self.db
    }

    // ============================================================
    // Conversion helpers
    // ============================================================

    fn batch_to_stored(batch: &Batch) -> StoredBatch {
        StoredBatch {
            worker_id: batch.worker_id,
            transactions: batch.transactions.clone(),
            timestamp: batch.timestamp,
        }
    }

    fn stored_to_batch(stored: StoredBatch, _hash: Hash) -> Batch {
        Batch {
            worker_id: stored.worker_id,
            transactions: stored.transactions,
            timestamp: stored.timestamp,
        }
    }

    fn car_to_stored(car: &Car) -> StoredCar {
        StoredCar {
            proposer: car.proposer.as_bytes().to_vec(),
            position: car.position,
            batch_digests: car
                .batch_digests
                .iter()
                .map(|bd| StoredBatchDigest {
                    worker_id: bd.worker_id,
                    hash: *bd.digest.as_bytes(),
                    tx_count: bd.tx_count,
                    size_bytes: bd.byte_size as u64,
                })
                .collect(),
            parent_ref: car.parent_ref.map(|h| *h.as_bytes()),
            signature: car.signature.to_bytes().to_vec(),
            hash: *car.hash().as_bytes(),
        }
    }

    fn stored_to_car(stored: StoredCar) -> Result<Car> {
        let proposer = ValidatorId::from_bytes(
            stored.proposer.as_slice().try_into().map_err(|_| {
                StorageError::Database("Invalid validator ID length".into())
            })?,
        );

        let batch_digests: Vec<BatchDigest> = stored
            .batch_digests
            .into_iter()
            .map(|bd| BatchDigest {
                worker_id: bd.worker_id,
                digest: Hash::from_bytes(bd.hash),
                tx_count: bd.tx_count,
                byte_size: bd.size_bytes as u32,
            })
            .collect();

        let parent_ref = stored.parent_ref.map(Hash::from_bytes);

        let sig_bytes: [u8; 96] = stored
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::Database("Invalid BLS signature length".into()))?;
        let signature = cipherbft_crypto::BlsSignature::from_bytes(&sig_bytes)
            .map_err(|e| StorageError::Database(format!("Invalid BLS signature: {}", e)))?;

        Ok(Car {
            proposer,
            position: stored.position,
            batch_digests,
            parent_ref,
            signature,
        })
    }

    fn attestation_to_stored(att: &AggregatedAttestation) -> StoredAggregatedAttestation {
        StoredAggregatedAttestation {
            car_hash: *att.car_hash.as_bytes(),
            car_position: att.car_position,
            car_proposer: att.car_proposer.as_bytes().to_vec(),
            aggregated_signature: att.aggregated_signature.to_bytes().to_vec(),
            signers_bitvec: att.validators.as_raw_slice().to_vec(),
            signer_count: att.count() as u32,
        }
    }

    fn stored_to_attestation(stored: StoredAggregatedAttestation) -> Result<AggregatedAttestation> {
        use bitvec::prelude::*;

        let car_proposer = ValidatorId::from_bytes(
            stored.car_proposer.as_slice().try_into().map_err(|_| {
                StorageError::Database("Invalid validator ID length".into())
            })?,
        );

        let agg_sig_bytes: [u8; 96] = stored
            .aggregated_signature
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::Database("Invalid aggregate signature length".into()))?;
        let aggregated_signature =
            cipherbft_crypto::BlsAggregateSignature::from_bytes(&agg_sig_bytes)
                .map_err(|e| StorageError::Database(format!("Invalid BLS signature: {}", e)))?;

        // Reconstruct bitvec from raw bytes
        let validators = BitVec::<u8, Lsb0>::from_vec(stored.signers_bitvec);

        Ok(AggregatedAttestation {
            car_hash: Hash::from_bytes(stored.car_hash),
            car_position: stored.car_position,
            car_proposer,
            aggregated_signature,
            validators,
        })
    }

    fn cut_to_stored(cut: &Cut) -> StoredCut {
        StoredCut {
            height: cut.height,
            cars: cut
                .cars
                .iter()
                .map(|(vid, car)| {
                    let car_hash = car.hash();
                    let attestation = cut.attestations.get(&car_hash).map(Self::attestation_to_stored);
                    super::tables::StoredCarEntry {
                        validator: vid.as_bytes().to_vec(),
                        car: Self::car_to_stored(car),
                        attestation,
                    }
                })
                .collect(),
        }
    }

    fn stored_to_cut(stored: StoredCut) -> Result<Cut> {
        let mut cut = Cut::new(stored.height);

        for entry in stored.cars {
            let validator = ValidatorId::from_bytes(
                entry.validator.as_slice().try_into().map_err(|_| {
                    StorageError::Database("Invalid validator ID length".into())
                })?,
            );

            let car = Self::stored_to_car(entry.car)?;
            let car_hash = car.hash();

            if let Some(stored_att) = entry.attestation {
                let attestation = Self::stored_to_attestation(stored_att)?;
                cut.attestations.insert(car_hash, attestation);
            }

            cut.cars.insert(validator, car);
        }

        Ok(cut)
    }
}

#[async_trait]
impl DclStore for MdbxDclStore {
    // ============================================================
    // Batch Operations
    // ============================================================

    async fn put_batch(&self, batch: Batch) -> Result<()> {
        let hash = batch.hash();
        let _stored = Self::batch_to_stored(&batch);
        let _key = HashKey::from_slice(hash.as_bytes());

        trace!(?hash, "Storing batch");

        // TODO: Implement actual MDBX write when tables are fully integrated
        debug!(?hash, "Batch stored (skeleton)");

        Ok(())
    }

    async fn get_batch(&self, hash: &Hash) -> Result<Option<Batch>> {
        let _key = HashKey::from_slice(hash.as_bytes());

        trace!(?hash, "Getting batch");

        // TODO: Implement actual MDBX read
        Ok(None)
    }

    async fn has_batch(&self, hash: &Hash) -> Result<bool> {
        Ok(self.get_batch(hash).await?.is_some())
    }

    async fn delete_batch(&self, hash: &Hash) -> Result<bool> {
        let _key = HashKey::from_slice(hash.as_bytes());

        trace!(?hash, "Deleting batch");

        // TODO: Implement actual MDBX delete
        Ok(false)
    }

    // ============================================================
    // Car Operations
    // ============================================================

    async fn put_car(&self, car: Car) -> Result<()> {
        let hash = car.hash();
        let _key = CarTableKey::new(car.proposer.as_bytes(), car.position);
        let _stored = Self::car_to_stored(&car);

        trace!(proposer = ?car.proposer, position = car.position, "Storing car");

        // TODO: Implement actual MDBX write
        // Also need to update secondary index (CarsByHash)
        debug!(?hash, "Car stored (skeleton)");

        Ok(())
    }

    async fn get_car(&self, validator: &ValidatorId, position: u64) -> Result<Option<Car>> {
        let _key = CarTableKey::new(validator.as_bytes(), position);

        trace!(?validator, position, "Getting car");

        // TODO: Implement actual MDBX read
        Ok(None)
    }

    async fn get_car_by_hash(&self, hash: &Hash) -> Result<Option<Car>> {
        let _key = HashKey::from_slice(hash.as_bytes());

        trace!(?hash, "Getting car by hash");

        // TODO: Look up in CarsByHash index, then fetch from Cars
        Ok(None)
    }

    async fn get_highest_car_position(&self, validator: &ValidatorId) -> Result<Option<u64>> {
        trace!(?validator, "Getting highest car position");

        // TODO: Implement cursor-based scan
        Ok(None)
    }

    async fn get_cars_range(&self, range: CarRange) -> Result<Vec<Car>> {
        trace!(?range.validator_id, start = range.start, end = ?range.end, "Getting cars range");

        // TODO: Implement range query
        Ok(Vec::new())
    }

    async fn has_car(&self, validator: &ValidatorId, position: u64) -> Result<bool> {
        Ok(self.get_car(validator, position).await?.is_some())
    }

    async fn delete_car(&self, validator: &ValidatorId, position: u64) -> Result<bool> {
        let _key = CarTableKey::new(validator.as_bytes(), position);

        trace!(?validator, position, "Deleting car");

        // TODO: Implement actual MDBX delete
        // Also need to update secondary index
        Ok(false)
    }

    // ============================================================
    // Attestation Operations
    // ============================================================

    async fn put_attestation(&self, attestation: AggregatedAttestation) -> Result<()> {
        let _key = HashKey::from_slice(attestation.car_hash.as_bytes());
        let _stored = Self::attestation_to_stored(&attestation);

        trace!(car_hash = ?attestation.car_hash, "Storing attestation");

        // TODO: Implement actual MDBX write
        debug!(car_hash = ?attestation.car_hash, "Attestation stored (skeleton)");

        Ok(())
    }

    async fn get_attestation(&self, car_hash: &Hash) -> Result<Option<AggregatedAttestation>> {
        let _key = HashKey::from_slice(car_hash.as_bytes());

        trace!(?car_hash, "Getting attestation");

        // TODO: Implement actual MDBX read
        Ok(None)
    }

    async fn has_attestation(&self, car_hash: &Hash) -> Result<bool> {
        Ok(self.get_attestation(car_hash).await?.is_some())
    }

    async fn delete_attestation(&self, car_hash: &Hash) -> Result<bool> {
        let _key = HashKey::from_slice(car_hash.as_bytes());

        trace!(?car_hash, "Deleting attestation");

        // TODO: Implement actual MDBX delete
        Ok(false)
    }

    // ============================================================
    // Cut Operations
    // ============================================================

    async fn put_pending_cut(&self, cut: Cut) -> Result<()> {
        let _stored = Self::cut_to_stored(&cut);

        trace!(height = cut.height, "Storing pending cut");

        // TODO: Implement actual MDBX write
        debug!(height = cut.height, "Pending cut stored (skeleton)");

        Ok(())
    }

    async fn get_pending_cut(&self, height: u64) -> Result<Option<Cut>> {
        trace!(height, "Getting pending cut");

        // TODO: Implement actual MDBX read
        Ok(None)
    }

    async fn get_all_pending_cuts(&self) -> Result<Vec<Cut>> {
        trace!("Getting all pending cuts");

        // TODO: Implement cursor scan
        Ok(Vec::new())
    }

    async fn finalize_cut(&self, height: u64) -> Result<Option<Cut>> {
        trace!(height, "Finalizing cut");

        // Get pending cut
        let cut = match self.get_pending_cut(height).await? {
            Some(cut) => cut,
            None => return Ok(None),
        };

        // Delete from pending
        self.delete_pending_cut(height).await?;

        // Insert into finalized
        self.put_finalized_cut(cut.clone()).await?;

        Ok(Some(cut))
    }

    async fn delete_pending_cut(&self, height: u64) -> Result<bool> {
        trace!(height, "Deleting pending cut");

        // TODO: Implement actual MDBX delete
        Ok(false)
    }

    async fn put_finalized_cut(&self, cut: Cut) -> Result<()> {
        let _stored = Self::cut_to_stored(&cut);

        trace!(height = cut.height, "Storing finalized cut");

        // TODO: Implement actual MDBX write
        debug!(height = cut.height, "Finalized cut stored (skeleton)");

        Ok(())
    }

    async fn get_finalized_cut(&self, height: u64) -> Result<Option<Cut>> {
        trace!(height, "Getting finalized cut");

        // TODO: Implement actual MDBX read
        Ok(None)
    }

    async fn get_latest_finalized_cut(&self) -> Result<Option<Cut>> {
        trace!("Getting latest finalized cut");

        // TODO: Implement cursor-based reverse scan
        Ok(None)
    }

    async fn get_finalized_cuts_range(&self, range: CutRange) -> Result<Vec<Cut>> {
        trace!(start = range.start, end = ?range.end, "Getting finalized cuts range");

        // TODO: Implement range query
        Ok(Vec::new())
    }

    // ============================================================
    // Garbage Collection
    // ============================================================

    async fn prune_before(&self, height: u64) -> Result<u64> {
        trace!(height, "Pruning before height");

        // TODO: Implement pruning logic
        // 1. Delete finalized cuts before height
        // 2. Delete unreferenced cars
        // 3. Delete unreferenced attestations
        // 4. Delete unreferenced batches

        Ok(0)
    }

    async fn stats(&self) -> Result<StorageStats> {
        // TODO: Implement actual stat collection
        Ok(StorageStats {
            batch_count: 0,
            car_count: 0,
            attestation_count: 0,
            pending_cut_count: 0,
            finalized_cut_count: 0,
            storage_bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require the mdbx feature and a test database.
    // These are integration tests that should be run separately.

    #[test]
    fn test_car_table_key_creation() {
        let validator_bytes = [1u8; 32];
        let key = CarTableKey::new(&validator_bytes, 42);
        assert_eq!(key.position, 42);
        assert_eq!(&key.validator_prefix[..], &validator_bytes[..20]);
    }
}
