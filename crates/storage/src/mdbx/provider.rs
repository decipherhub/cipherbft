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
use reth_db_api::transaction::DbTx;
use std::sync::Arc;
use tracing::{debug, trace};

use super::database::Database;
use super::tables::{
    CarTableKey, HashKey, StoredAggregatedAttestation, StoredBatch, StoredBatchDigest, StoredCar,
    StoredCut,
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

    #[allow(dead_code)]
    fn batch_to_stored(batch: &Batch) -> StoredBatch {
        StoredBatch {
            worker_id: batch.worker_id,
            transactions: batch.transactions.clone(),
            timestamp: batch.timestamp,
        }
    }

    #[allow(dead_code)]
    fn stored_to_batch(stored: StoredBatch, _hash: Hash) -> Batch {
        Batch {
            worker_id: stored.worker_id,
            transactions: stored.transactions,
            timestamp: stored.timestamp,
        }
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    fn stored_to_car(stored: StoredCar) -> Result<Car> {
        let proposer = ValidatorId::from_bytes(
            stored
                .proposer
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Database("Invalid validator ID length".into()))?,
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
            .map_err(|e| StorageError::Database(format!("Invalid BLS signature: {e}")))?;

        Ok(Car {
            proposer,
            position: stored.position,
            batch_digests,
            parent_ref,
            signature,
        })
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    fn stored_to_attestation(stored: StoredAggregatedAttestation) -> Result<AggregatedAttestation> {
        use bitvec::prelude::*;

        let car_proposer = ValidatorId::from_bytes(
            stored
                .car_proposer
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Database("Invalid validator ID length".into()))?,
        );

        let agg_sig_bytes: [u8; 96] = stored
            .aggregated_signature
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::Database("Invalid aggregate signature length".into()))?;
        let aggregated_signature =
            cipherbft_crypto::BlsAggregateSignature::from_bytes(&agg_sig_bytes)
                .map_err(|e| StorageError::Database(format!("Invalid BLS signature: {e}")))?;

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

    #[allow(dead_code)]
    fn cut_to_stored(cut: &Cut) -> StoredCut {
        StoredCut {
            height: cut.height,
            cars: cut
                .cars
                .iter()
                .map(|(vid, car)| {
                    let car_hash = car.hash();
                    let attestation = cut
                        .attestations
                        .get(&car_hash)
                        .map(Self::attestation_to_stored);
                    super::tables::StoredCarEntry {
                        validator: vid.as_bytes().to_vec(),
                        car: Self::car_to_stored(car),
                        attestation,
                    }
                })
                .collect(),
        }
    }

    #[allow(dead_code)]
    fn stored_to_cut(stored: StoredCut) -> Result<Cut> {
        let mut cut = Cut::new(stored.height);

        for entry in stored.cars {
            let validator =
                ValidatorId::from_bytes(
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
        use super::tables::{Batches, BincodeValue};
        use reth_db_api::transaction::DbTxMut;

        let hash = batch.hash();
        let stored = Self::batch_to_stored(&batch);
        let key = HashKey::from_slice(hash.as_bytes());

        trace!(?hash, "Storing batch");

        let tx = self.db.tx_mut()?;
        tx.put::<Batches>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put batch: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit batch: {e}")))?;

        debug!(?hash, "Batch stored");
        Ok(())
    }

    async fn get_batch(&self, hash: &Hash) -> Result<Option<Batch>> {
        use super::tables::Batches;
        use reth_db_api::transaction::DbTx;

        let key = HashKey::from_slice(hash.as_bytes());

        trace!(?hash, "Getting batch");

        let tx = self.db.tx()?;
        let result = tx
            .get::<Batches>(key)
            .map_err(|e| StorageError::Database(format!("Failed to get batch: {e}")))?;

        match result {
            Some(bincode_value) => {
                let batch = Self::stored_to_batch(bincode_value.0, *hash);
                Ok(Some(batch))
            }
            None => Ok(None),
        }
    }

    async fn has_batch(&self, hash: &Hash) -> Result<bool> {
        Ok(self.get_batch(hash).await?.is_some())
    }

    async fn delete_batch(&self, hash: &Hash) -> Result<bool> {
        use super::tables::Batches;
        use reth_db_api::transaction::DbTxMut;

        let key = HashKey::from_slice(hash.as_bytes());

        trace!(?hash, "Deleting batch");

        let tx = self.db.tx_mut()?;
        let existed = tx
            .get::<Batches>(key)
            .map_err(|e| StorageError::Database(format!("Failed to check batch: {e}")))?
            .is_some();

        if existed {
            tx.delete::<Batches>(key, None)
                .map_err(|e| StorageError::Database(format!("Failed to delete batch: {e}")))?;
            tx.commit()
                .map_err(|e| StorageError::Database(format!("Failed to commit delete: {e}")))?;
            debug!(?hash, "Batch deleted");
        }

        Ok(existed)
    }

    // ============================================================
    // Car Operations
    // ============================================================

    async fn put_car(&self, car: Car) -> Result<()> {
        use super::tables::{BincodeValue, Cars, CarsByHash};
        use reth_db_api::transaction::DbTxMut;

        let hash = car.hash();
        let key = CarTableKey::new(car.proposer.as_bytes(), car.position);
        let stored = Self::car_to_stored(&car);
        let hash_key = HashKey::from_slice(hash.as_bytes());

        trace!(proposer = ?car.proposer, position = car.position, "Storing car");

        let tx = self.db.tx_mut()?;

        // Store the car
        tx.put::<Cars>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put car: {e}")))?;

        // Maintain secondary index (CarsByHash)
        tx.put::<CarsByHash>(hash_key, key)
            .map_err(|e| StorageError::Database(format!("Failed to put car index: {e}")))?;

        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit car: {e}")))?;

        debug!(?hash, "Car stored");
        Ok(())
    }

    async fn get_car(&self, validator: &ValidatorId, position: u64) -> Result<Option<Car>> {
        use super::tables::Cars;
        use reth_db_api::transaction::DbTx;

        let key = CarTableKey::new(validator.as_bytes(), position);

        trace!(?validator, position, "Getting car");

        let tx = self.db.tx()?;
        let result = tx
            .get::<Cars>(key)
            .map_err(|e| StorageError::Database(format!("Failed to get car: {e}")))?;

        match result {
            Some(bincode_value) => {
                let car = Self::stored_to_car(bincode_value.0)?;
                Ok(Some(car))
            }
            None => Ok(None),
        }
    }

    async fn get_car_by_hash(&self, hash: &Hash) -> Result<Option<Car>> {
        use super::tables::{Cars, CarsByHash};
        use reth_db_api::transaction::DbTx;

        let hash_key = HashKey::from_slice(hash.as_bytes());

        trace!(?hash, "Getting car by hash");

        let tx = self.db.tx()?;

        // Look up the car key in the secondary index
        let car_key = tx
            .get::<CarsByHash>(hash_key)
            .map_err(|e| StorageError::Database(format!("Failed to get car index: {e}")))?;

        match car_key {
            Some(key) => {
                // Fetch the actual car
                let result = tx
                    .get::<Cars>(key)
                    .map_err(|e| StorageError::Database(format!("Failed to get car: {e}")))?;

                match result {
                    Some(bincode_value) => {
                        let car = Self::stored_to_car(bincode_value.0)?;
                        Ok(Some(car))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn get_highest_car_position(&self, validator: &ValidatorId) -> Result<Option<u64>> {
        use super::tables::Cars;
        use reth_db_api::cursor::DbCursorRO;
        use reth_db_api::transaction::DbTx;

        trace!(?validator, "Getting highest car position");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<Cars>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        // Create a key with max position for the validator to seek backwards
        let validator_prefix: [u8; 20] = {
            let bytes = validator.as_bytes();
            let mut arr = [0u8; 20];
            let copy_len = bytes.len().min(20);
            arr[..copy_len].copy_from_slice(&bytes[..copy_len]);
            arr
        };

        // Create key for next validator (to set upper bound)
        let mut next_prefix = validator_prefix;
        let mut carry = true;
        for i in (0..20).rev() {
            if carry {
                if next_prefix[i] == 0xFF {
                    next_prefix[i] = 0;
                } else {
                    next_prefix[i] += 1;
                    carry = false;
                }
            }
        }

        // Seek to the position just before the next validator
        let seek_key = CarTableKey {
            validator_prefix: next_prefix,
            position: 0,
        };

        // Use prev to find the last entry for this validator
        if cursor
            .seek(seek_key)
            .map_err(|e| StorageError::Database(format!("Cursor seek failed: {e}")))?
            .is_some()
        {
            // Go to previous entry
            if let Some((key, _)) = cursor
                .prev()
                .map_err(|e| StorageError::Database(format!("Cursor prev failed: {e}")))?
            {
                if key.validator_prefix == validator_prefix {
                    return Ok(Some(key.position));
                }
            }
        } else {
            // We're at the end, try last
            if let Some((key, _)) = cursor
                .last()
                .map_err(|e| StorageError::Database(format!("Cursor last failed: {e}")))?
            {
                if key.validator_prefix == validator_prefix {
                    return Ok(Some(key.position));
                }
            }
        }

        Ok(None)
    }

    async fn get_cars_range(&self, range: CarRange) -> Result<Vec<Car>> {
        use super::tables::Cars;
        use reth_db_api::cursor::DbCursorRO;
        use reth_db_api::transaction::DbTx;

        trace!(?range.validator_id, start = range.start, end = ?range.end, "Getting cars range");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<Cars>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        let start_key = CarTableKey::new(range.validator_id.as_bytes(), range.start);
        let end_position = range.end.unwrap_or(u64::MAX);

        let mut cars = Vec::new();

        // Seek to start position
        let mut current = cursor
            .seek(start_key)
            .map_err(|e| StorageError::Database(format!("Cursor seek failed: {e}")))?;

        let validator_prefix: [u8; 20] = {
            let bytes = range.validator_id.as_bytes();
            let mut arr = [0u8; 20];
            let copy_len = bytes.len().min(20);
            arr[..copy_len].copy_from_slice(&bytes[..copy_len]);
            arr
        };

        while let Some((key, value)) = current {
            // Check if we're still within the same validator
            if key.validator_prefix != validator_prefix {
                break;
            }

            // Check if we're past the end position
            if key.position > end_position {
                break;
            }

            // Convert and add the car
            let car = Self::stored_to_car(value.0)?;
            cars.push(car);

            // Move to next
            current = cursor
                .next()
                .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
        }

        Ok(cars)
    }

    async fn has_car(&self, validator: &ValidatorId, position: u64) -> Result<bool> {
        Ok(self.get_car(validator, position).await?.is_some())
    }

    async fn delete_car(&self, validator: &ValidatorId, position: u64) -> Result<bool> {
        use super::tables::{Cars, CarsByHash};
        use reth_db_api::transaction::DbTxMut;

        let key = CarTableKey::new(validator.as_bytes(), position);

        trace!(?validator, position, "Deleting car");

        let tx = self.db.tx_mut()?;

        // Get the car first to find its hash for index cleanup
        let car_result = tx
            .get::<Cars>(key)
            .map_err(|e| StorageError::Database(format!("Failed to get car: {e}")))?;

        match car_result {
            Some(bincode_value) => {
                let hash = bincode_value.0.hash;
                let hash_key = HashKey::from_slice(&hash);

                // Delete from Cars table
                tx.delete::<Cars>(key, None)
                    .map_err(|e| StorageError::Database(format!("Failed to delete car: {e}")))?;

                // Delete from secondary index
                tx.delete::<CarsByHash>(hash_key, None).map_err(|e| {
                    StorageError::Database(format!("Failed to delete car index: {e}"))
                })?;

                tx.commit()
                    .map_err(|e| StorageError::Database(format!("Failed to commit delete: {e}")))?;

                debug!(?validator, position, "Car deleted");
                Ok(true)
            }
            None => Ok(false),
        }
    }

    // ============================================================
    // Attestation Operations
    // ============================================================

    async fn put_attestation(&self, attestation: AggregatedAttestation) -> Result<()> {
        use super::tables::{Attestations, BincodeValue};
        use reth_db_api::transaction::DbTxMut;

        let key = HashKey::from_slice(attestation.car_hash.as_bytes());
        let stored = Self::attestation_to_stored(&attestation);

        trace!(car_hash = ?attestation.car_hash, "Storing attestation");

        let tx = self.db.tx_mut()?;
        tx.put::<Attestations>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put attestation: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit attestation: {e}")))?;

        debug!(car_hash = ?attestation.car_hash, "Attestation stored");
        Ok(())
    }

    async fn get_attestation(&self, car_hash: &Hash) -> Result<Option<AggregatedAttestation>> {
        use super::tables::Attestations;
        use reth_db_api::transaction::DbTx;

        let key = HashKey::from_slice(car_hash.as_bytes());

        trace!(?car_hash, "Getting attestation");

        let tx = self.db.tx()?;
        let result = tx
            .get::<Attestations>(key)
            .map_err(|e| StorageError::Database(format!("Failed to get attestation: {e}")))?;

        match result {
            Some(bincode_value) => {
                let attestation = Self::stored_to_attestation(bincode_value.0)?;
                Ok(Some(attestation))
            }
            None => Ok(None),
        }
    }

    async fn has_attestation(&self, car_hash: &Hash) -> Result<bool> {
        Ok(self.get_attestation(car_hash).await?.is_some())
    }

    async fn delete_attestation(&self, car_hash: &Hash) -> Result<bool> {
        use super::tables::Attestations;
        use reth_db_api::transaction::DbTxMut;

        let key = HashKey::from_slice(car_hash.as_bytes());

        trace!(?car_hash, "Deleting attestation");

        let tx = self.db.tx_mut()?;
        let existed = tx
            .get::<Attestations>(key)
            .map_err(|e| StorageError::Database(format!("Failed to check attestation: {e}")))?
            .is_some();

        if existed {
            tx.delete::<Attestations>(key, None).map_err(|e| {
                StorageError::Database(format!("Failed to delete attestation: {e}"))
            })?;
            tx.commit()
                .map_err(|e| StorageError::Database(format!("Failed to commit delete: {e}")))?;
            debug!(?car_hash, "Attestation deleted");
        }

        Ok(existed)
    }

    // ============================================================
    // Cut Operations
    // ============================================================

    async fn put_pending_cut(&self, cut: Cut) -> Result<()> {
        use super::tables::{BincodeValue, HeightKey, PendingCuts};
        use reth_db_api::transaction::DbTxMut;

        let stored = Self::cut_to_stored(&cut);
        let key = HeightKey::new(cut.height);

        trace!(height = cut.height, "Storing pending cut");

        let tx = self.db.tx_mut()?;
        tx.put::<PendingCuts>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put pending cut: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit pending cut: {e}")))?;

        debug!(height = cut.height, "Pending cut stored");
        Ok(())
    }

    async fn get_pending_cut(&self, height: u64) -> Result<Option<Cut>> {
        use super::tables::{HeightKey, PendingCuts};
        use reth_db_api::transaction::DbTx;

        let key = HeightKey::new(height);

        trace!(height, "Getting pending cut");

        let tx = self.db.tx()?;
        let result = tx
            .get::<PendingCuts>(key)
            .map_err(|e| StorageError::Database(format!("Failed to get pending cut: {e}")))?;

        match result {
            Some(bincode_value) => {
                let cut = Self::stored_to_cut(bincode_value.0)?;
                Ok(Some(cut))
            }
            None => Ok(None),
        }
    }

    async fn get_all_pending_cuts(&self) -> Result<Vec<Cut>> {
        use super::tables::PendingCuts;
        use reth_db_api::cursor::DbCursorRO;
        use reth_db_api::transaction::DbTx;

        trace!("Getting all pending cuts");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<PendingCuts>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        let mut cuts = Vec::new();
        let mut current = cursor
            .first()
            .map_err(|e| StorageError::Database(format!("Cursor first failed: {e}")))?;

        while let Some((_, value)) = current {
            let cut = Self::stored_to_cut(value.0)?;
            cuts.push(cut);

            current = cursor
                .next()
                .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
        }

        Ok(cuts)
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
        use super::tables::{HeightKey, PendingCuts};
        use reth_db_api::transaction::DbTxMut;

        let key = HeightKey::new(height);

        trace!(height, "Deleting pending cut");

        let tx = self.db.tx_mut()?;
        let existed = tx
            .get::<PendingCuts>(key)
            .map_err(|e| StorageError::Database(format!("Failed to check pending cut: {e}")))?
            .is_some();

        if existed {
            tx.delete::<PendingCuts>(key, None).map_err(|e| {
                StorageError::Database(format!("Failed to delete pending cut: {e}"))
            })?;
            tx.commit()
                .map_err(|e| StorageError::Database(format!("Failed to commit delete: {e}")))?;
            debug!(height, "Pending cut deleted");
        }

        Ok(existed)
    }

    async fn put_finalized_cut(&self, cut: Cut) -> Result<()> {
        use super::tables::{BincodeValue, FinalizedCuts, HeightKey};
        use reth_db_api::transaction::DbTxMut;

        let stored = Self::cut_to_stored(&cut);
        let key = HeightKey::new(cut.height);

        trace!(height = cut.height, "Storing finalized cut");

        let tx = self.db.tx_mut()?;
        tx.put::<FinalizedCuts>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put finalized cut: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit finalized cut: {e}")))?;

        debug!(height = cut.height, "Finalized cut stored");
        Ok(())
    }

    async fn get_finalized_cut(&self, height: u64) -> Result<Option<Cut>> {
        use super::tables::{FinalizedCuts, HeightKey};
        use reth_db_api::transaction::DbTx;

        let key = HeightKey::new(height);

        trace!(height, "Getting finalized cut");

        let tx = self.db.tx()?;
        let result = tx
            .get::<FinalizedCuts>(key)
            .map_err(|e| StorageError::Database(format!("Failed to get finalized cut: {e}")))?;

        match result {
            Some(bincode_value) => {
                let cut = Self::stored_to_cut(bincode_value.0)?;
                Ok(Some(cut))
            }
            None => Ok(None),
        }
    }

    async fn get_latest_finalized_cut(&self) -> Result<Option<Cut>> {
        use super::tables::FinalizedCuts;
        use reth_db_api::cursor::DbCursorRO;
        use reth_db_api::transaction::DbTx;

        trace!("Getting latest finalized cut");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<FinalizedCuts>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        // Get the last entry (highest height due to big-endian ordering)
        let result = cursor
            .last()
            .map_err(|e| StorageError::Database(format!("Cursor last failed: {e}")))?;

        match result {
            Some((_, value)) => {
                let cut = Self::stored_to_cut(value.0)?;
                Ok(Some(cut))
            }
            None => Ok(None),
        }
    }

    async fn get_finalized_cuts_range(&self, range: CutRange) -> Result<Vec<Cut>> {
        use super::tables::{FinalizedCuts, HeightKey};
        use reth_db_api::cursor::DbCursorRO;
        use reth_db_api::transaction::DbTx;

        trace!(start = range.start, end = ?range.end, "Getting finalized cuts range");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<FinalizedCuts>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        let start_key = HeightKey::new(range.start);
        let end_height = range.end.unwrap_or(u64::MAX);

        let mut cuts = Vec::new();

        // Seek to start position
        let mut current = cursor
            .seek(start_key)
            .map_err(|e| StorageError::Database(format!("Cursor seek failed: {e}")))?;

        while let Some((key, value)) = current {
            // Check if we're past the end height
            if key.0 > end_height {
                break;
            }

            // Convert and add the cut
            let cut = Self::stored_to_cut(value.0)?;
            cuts.push(cut);

            // Move to next
            current = cursor
                .next()
                .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
        }

        Ok(cuts)
    }

    // ============================================================
    // Garbage Collection
    // ============================================================

    async fn prune_before(&self, height: u64) -> Result<u64> {
        use super::tables::{
            Attestations, Batches, Cars, CarsByHash, FinalizedCuts, HashKey, HeightKey,
        };
        use reth_db_api::cursor::{DbCursorRO, DbCursorRW};
        use reth_db_api::transaction::DbTxMut;
        use std::collections::HashSet;

        trace!(height, "Pruning before height with reference tracking");

        // Phase 1: Collect all referenced Car hashes and Batch hashes from retained Cuts
        let mut retained_car_hashes: HashSet<[u8; 32]> = HashSet::new();
        let mut retained_batch_hashes: HashSet<[u8; 32]> = HashSet::new();

        {
            let tx = self.db.tx()?;
            let mut cursor = tx
                .cursor_read::<FinalizedCuts>()
                .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

            // Seek to the threshold height
            let mut current = cursor
                .seek(HeightKey::new(height))
                .map_err(|e| StorageError::Database(format!("Cursor seek failed: {e}")))?;

            // Collect all references from retained Cuts (height >= threshold)
            while let Some((_, value)) = current {
                for car_entry in &value.0.cars {
                    retained_car_hashes.insert(car_entry.car.hash);
                    for batch_digest in &car_entry.car.batch_digests {
                        retained_batch_hashes.insert(batch_digest.hash);
                    }
                }
                current = cursor
                    .next()
                    .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
            }
        }

        debug!(
            retained_cars = retained_car_hashes.len(),
            retained_batches = retained_batch_hashes.len(),
            "Collected retained references"
        );

        // Phase 2: Collect Car hashes and Batch hashes to prune from Cuts below threshold
        let mut car_hashes_to_prune: HashSet<[u8; 32]> = HashSet::new();
        let mut batch_hashes_to_prune: HashSet<[u8; 32]> = HashSet::new();
        let mut car_keys_to_delete: Vec<CarTableKey> = Vec::new();

        {
            let tx = self.db.tx()?;
            let mut cursor = tx
                .cursor_read::<FinalizedCuts>()
                .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

            let mut current = cursor
                .first()
                .map_err(|e| StorageError::Database(format!("Cursor first failed: {e}")))?;

            while let Some((key, value)) = current {
                if key.0 >= height {
                    break;
                }

                for car_entry in &value.0.cars {
                    let car_hash = car_entry.car.hash;

                    // Only prune if not retained by any higher Cut
                    if !retained_car_hashes.contains(&car_hash) {
                        car_hashes_to_prune.insert(car_hash);

                        // Build car key for deletion
                        let validator_bytes = &car_entry.validator;
                        if validator_bytes.len() >= 20 {
                            let mut validator_prefix = [0u8; 20];
                            validator_prefix.copy_from_slice(&validator_bytes[..20]);
                            car_keys_to_delete.push(CarTableKey {
                                validator_prefix,
                                position: car_entry.car.position,
                            });
                        }

                        // Collect batch hashes for pruning
                        for batch_digest in &car_entry.car.batch_digests {
                            if !retained_batch_hashes.contains(&batch_digest.hash) {
                                batch_hashes_to_prune.insert(batch_digest.hash);
                            }
                        }
                    }
                }

                current = cursor
                    .next()
                    .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
            }
        }

        debug!(
            cars_to_prune = car_hashes_to_prune.len(),
            batches_to_prune = batch_hashes_to_prune.len(),
            "Collected items to prune"
        );

        // Phase 3: Perform deletions in a single transaction
        let tx = self.db.tx_mut()?;
        let mut pruned_count = 0u64;

        // 3a: Delete FinalizedCuts below threshold
        {
            let mut cursor = tx
                .cursor_write::<FinalizedCuts>()
                .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

            let mut current = cursor
                .first()
                .map_err(|e| StorageError::Database(format!("Cursor first failed: {e}")))?;

            while let Some((key, _)) = current {
                if key.0 >= height {
                    break;
                }

                cursor
                    .delete_current()
                    .map_err(|e| StorageError::Database(format!("Failed to delete cut: {e}")))?;
                pruned_count += 1;

                current = cursor
                    .next()
                    .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
            }
        }

        // 3b: Delete Cars and their CarsByHash index entries
        for car_key in &car_keys_to_delete {
            // Delete from Cars table
            tx.delete::<Cars>(*car_key, None)
                .map_err(|e| StorageError::Database(format!("Failed to delete car: {e}")))?;
            pruned_count += 1;
        }

        for car_hash in &car_hashes_to_prune {
            // Delete from CarsByHash index
            tx.delete::<CarsByHash>(HashKey(*car_hash), None)
                .map_err(|e| {
                    StorageError::Database(format!("Failed to delete car hash index: {e}"))
                })?;
        }

        // 3c: Delete Attestations for pruned Cars
        for car_hash in &car_hashes_to_prune {
            tx.delete::<Attestations>(HashKey(*car_hash), None)
                .map_err(|e| {
                    StorageError::Database(format!("Failed to delete attestation: {e}"))
                })?;
            pruned_count += 1;
        }

        // 3d: Delete unreferenced Batches
        for batch_hash in &batch_hashes_to_prune {
            tx.delete::<Batches>(HashKey(*batch_hash), None)
                .map_err(|e| StorageError::Database(format!("Failed to delete batch: {e}")))?;
            pruned_count += 1;
        }

        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit prune: {e}")))?;

        debug!(
            height,
            pruned_count,
            cuts_pruned = car_keys_to_delete.len(),
            cars_pruned = car_hashes_to_prune.len(),
            attestations_pruned = car_hashes_to_prune.len(),
            batches_pruned = batch_hashes_to_prune.len(),
            "Pruning completed with reference tracking"
        );
        Ok(pruned_count)
    }

    async fn stats(&self) -> Result<StorageStats> {
        use super::tables::{Attestations, Batches, Cars, FinalizedCuts, PendingCuts};
        use reth_db_api::cursor::DbCursorRO;
        use reth_db_api::transaction::DbTx;

        let tx = self.db.tx()?;

        // Count entries in each table
        let batch_count = {
            let mut cursor = tx
                .cursor_read::<Batches>()
                .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;
            let mut count = 0u64;
            let mut current = cursor
                .first()
                .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            while current.is_some() {
                count += 1;
                current = cursor
                    .next()
                    .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            }
            count
        };

        let car_count = {
            let mut cursor = tx
                .cursor_read::<Cars>()
                .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;
            let mut count = 0u64;
            let mut current = cursor
                .first()
                .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            while current.is_some() {
                count += 1;
                current = cursor
                    .next()
                    .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            }
            count
        };

        let attestation_count = {
            let mut cursor = tx
                .cursor_read::<Attestations>()
                .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;
            let mut count = 0u64;
            let mut current = cursor
                .first()
                .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            while current.is_some() {
                count += 1;
                current = cursor
                    .next()
                    .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            }
            count
        };

        let pending_cut_count = {
            let mut cursor = tx
                .cursor_read::<PendingCuts>()
                .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;
            let mut count = 0u64;
            let mut current = cursor
                .first()
                .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            while current.is_some() {
                count += 1;
                current = cursor
                    .next()
                    .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            }
            count
        };

        let finalized_cut_count = {
            let mut cursor = tx
                .cursor_read::<FinalizedCuts>()
                .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;
            let mut count = 0u64;
            let mut current = cursor
                .first()
                .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            while current.is_some() {
                count += 1;
                current = cursor
                    .next()
                    .map_err(|e| StorageError::Database(format!("Cursor failed: {e}")))?;
            }
            count
        };

        // Get storage size from database stats
        let db_stats = self.db.stats()?;
        let storage_bytes = (db_stats.leaf_pages + db_stats.branch_pages + db_stats.overflow_pages)
            * db_stats.page_size as u64;

        Ok(StorageStats {
            batch_count,
            car_count,
            attestation_count,
            pending_cut_count,
            finalized_cut_count,
            storage_bytes,
        })
    }
}

// ============================================================
// Transaction Support
// ============================================================

use crate::dcl::{DclStoreExt, DclStoreTx};
use reth_db::DatabaseEnv;
use reth_db_api::transaction::DbTxMut;

type MdbxTx = <DatabaseEnv as reth_db_api::database::Database>::TXMut;

/// MDBX transaction wrapper for atomic batch operations
pub struct MdbxDclStoreTx {
    /// The underlying MDBX write transaction
    tx: Option<MdbxTx>,
}

impl MdbxDclStoreTx {
    /// Create a new transaction wrapper
    fn new(tx: MdbxTx) -> Self {
        Self { tx: Some(tx) }
    }

    /// Get a mutable reference to the transaction
    fn tx_mut(&mut self) -> Result<&mut MdbxTx> {
        self.tx
            .as_mut()
            .ok_or_else(|| StorageError::Database("Transaction already consumed".into()))
    }

    /// Take ownership of the transaction
    fn take_tx(&mut self) -> Result<MdbxTx> {
        self.tx
            .take()
            .ok_or_else(|| StorageError::Database("Transaction already consumed".into()))
    }
}

#[async_trait]
impl DclStoreTx for MdbxDclStoreTx {
    async fn commit(mut self) -> Result<()> {
        let tx = self.take_tx()?;
        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit transaction: {e}")))?;
        debug!("Transaction committed");
        Ok(())
    }

    async fn abort(mut self) -> Result<()> {
        let tx = self.take_tx()?;
        tx.abort();
        debug!("Transaction aborted");
        Ok(())
    }

    async fn put_batch(&mut self, batch: Batch) -> Result<()> {
        use super::tables::{Batches, BincodeValue};

        let hash = batch.hash();
        let stored = MdbxDclStore::batch_to_stored(&batch);
        let key = HashKey::from_slice(hash.as_bytes());

        let tx = self.tx_mut()?;
        tx.put::<Batches>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put batch: {e}")))?;

        trace!(?hash, "Batch added to transaction");
        Ok(())
    }

    async fn put_car(&mut self, car: Car) -> Result<()> {
        use super::tables::{BincodeValue, Cars, CarsByHash};

        let hash = car.hash();
        let key = CarTableKey::new(car.proposer.as_bytes(), car.position);
        let stored = MdbxDclStore::car_to_stored(&car);
        let hash_key = HashKey::from_slice(hash.as_bytes());

        let tx = self.tx_mut()?;
        tx.put::<Cars>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put car: {e}")))?;
        tx.put::<CarsByHash>(hash_key, key)
            .map_err(|e| StorageError::Database(format!("Failed to put car index: {e}")))?;

        trace!(?hash, "Car added to transaction");
        Ok(())
    }

    async fn put_attestation(&mut self, attestation: AggregatedAttestation) -> Result<()> {
        use super::tables::{Attestations, BincodeValue};

        let key = HashKey::from_slice(attestation.car_hash.as_bytes());
        let stored = MdbxDclStore::attestation_to_stored(&attestation);

        let tx = self.tx_mut()?;
        tx.put::<Attestations>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put attestation: {e}")))?;

        trace!(car_hash = ?attestation.car_hash, "Attestation added to transaction");
        Ok(())
    }

    async fn put_pending_cut(&mut self, cut: Cut) -> Result<()> {
        use super::tables::{BincodeValue, HeightKey, PendingCuts};

        let stored = MdbxDclStore::cut_to_stored(&cut);
        let key = HeightKey::new(cut.height);

        let tx = self.tx_mut()?;
        tx.put::<PendingCuts>(key, BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put pending cut: {e}")))?;

        trace!(height = cut.height, "Pending cut added to transaction");
        Ok(())
    }

    async fn finalize_cut(&mut self, height: u64) -> Result<Option<Cut>> {
        use super::tables::{FinalizedCuts, HeightKey, PendingCuts};

        let key = HeightKey::new(height);
        let tx = self.tx_mut()?;

        // Get the pending cut
        let pending = tx
            .get::<PendingCuts>(key)
            .map_err(|e| StorageError::Database(format!("Failed to get pending cut: {e}")))?;

        match pending {
            Some(bincode_value) => {
                // Delete from pending
                tx.delete::<PendingCuts>(key, None).map_err(|e| {
                    StorageError::Database(format!("Failed to delete pending cut: {e}"))
                })?;

                // Insert into finalized
                tx.put::<FinalizedCuts>(key, bincode_value.clone())
                    .map_err(|e| {
                        StorageError::Database(format!("Failed to put finalized cut: {e}"))
                    })?;

                let cut = MdbxDclStore::stored_to_cut(bincode_value.0)?;
                trace!(height, "Cut finalized in transaction");
                Ok(Some(cut))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl DclStoreExt for MdbxDclStore {
    type Transaction = MdbxDclStoreTx;

    async fn begin_tx(&self) -> Result<Self::Transaction> {
        use reth_db_api::database::Database as DbTrait;

        let tx = self
            .db
            .env()
            .tx_mut()
            .map_err(|e| StorageError::Database(format!("Failed to begin transaction: {e}")))?;

        debug!("Transaction started");
        Ok(MdbxDclStoreTx::new(tx))
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
