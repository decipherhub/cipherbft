//! In-memory implementation of DclStore
//!
//! This implementation is primarily for testing and development.
//! It stores all data in memory using concurrent hash maps.

use crate::dcl::{DclStore, StorageStats};
use crate::error::{Result, StorageError};
use crate::tables::CarRange;
use crate::tables::CutRange;
use async_trait::async_trait;
use cipherbft_data_chain::{AggregatedAttestation, Batch, Car, Cut};
use cipherbft_types::{Hash, ValidatorId};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap};

/// In-memory DCL store implementation
///
/// Uses parking_lot RwLock for thread-safe concurrent access.
pub struct InMemoryStore {
    /// Batches indexed by hash
    batches: RwLock<HashMap<Hash, Batch>>,

    /// Cars indexed by (ValidatorId, position)
    cars: RwLock<HashMap<(ValidatorId, u64), Car>>,

    /// Car hash to (ValidatorId, position) mapping
    car_index: RwLock<HashMap<Hash, (ValidatorId, u64)>>,

    /// Highest position for each validator
    highest_positions: RwLock<HashMap<ValidatorId, u64>>,

    /// Aggregated attestations indexed by Car hash
    attestations: RwLock<HashMap<Hash, AggregatedAttestation>>,

    /// Pending Cuts indexed by height
    pending_cuts: RwLock<BTreeMap<u64, Cut>>,

    /// Finalized Cuts indexed by height
    finalized_cuts: RwLock<BTreeMap<u64, Cut>>,
}

impl InMemoryStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self {
            batches: RwLock::new(HashMap::new()),
            cars: RwLock::new(HashMap::new()),
            car_index: RwLock::new(HashMap::new()),
            highest_positions: RwLock::new(HashMap::new()),
            attestations: RwLock::new(HashMap::new()),
            pending_cuts: RwLock::new(BTreeMap::new()),
            finalized_cuts: RwLock::new(BTreeMap::new()),
        }
    }

    /// Clear all data (for testing)
    pub fn clear(&self) {
        self.batches.write().clear();
        self.cars.write().clear();
        self.car_index.write().clear();
        self.highest_positions.write().clear();
        self.attestations.write().clear();
        self.pending_cuts.write().clear();
        self.finalized_cuts.write().clear();
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DclStore for InMemoryStore {
    // ============================================================
    // Batch Operations
    // ============================================================

    async fn put_batch(&self, batch: Batch) -> Result<()> {
        let hash = batch.hash();
        let mut batches = self.batches.write();

        if batches.contains_key(&hash) {
            return Err(StorageError::DuplicateEntry(format!("batch {hash}")));
        }

        batches.insert(hash, batch);
        Ok(())
    }

    async fn get_batch(&self, hash: &Hash) -> Result<Option<Batch>> {
        let batches = self.batches.read();
        Ok(batches.get(hash).cloned())
    }

    async fn has_batch(&self, hash: &Hash) -> Result<bool> {
        let batches = self.batches.read();
        Ok(batches.contains_key(hash))
    }

    async fn delete_batch(&self, hash: &Hash) -> Result<bool> {
        let mut batches = self.batches.write();
        Ok(batches.remove(hash).is_some())
    }

    // ============================================================
    // Car Operations
    // ============================================================

    async fn put_car(&self, car: Car) -> Result<()> {
        let key = (car.proposer, car.position);
        let hash = car.hash();

        let mut cars = self.cars.write();
        let mut car_index = self.car_index.write();
        let mut highest_positions = self.highest_positions.write();

        if cars.contains_key(&key) {
            return Err(StorageError::DuplicateEntry(format!(
                "car {} at position {}",
                car.proposer, car.position
            )));
        }

        // Update highest position
        let current_highest = highest_positions.get(&car.proposer).copied();
        if current_highest.is_none() || car.position > current_highest.unwrap() {
            highest_positions.insert(car.proposer, car.position);
        }

        car_index.insert(hash, key);
        cars.insert(key, car);
        Ok(())
    }

    async fn get_car(&self, validator: &ValidatorId, position: u64) -> Result<Option<Car>> {
        let cars = self.cars.read();
        Ok(cars.get(&(*validator, position)).cloned())
    }

    async fn get_car_by_hash(&self, hash: &Hash) -> Result<Option<Car>> {
        let car_index = self.car_index.read();
        let cars = self.cars.read();

        match car_index.get(hash) {
            Some(key) => Ok(cars.get(key).cloned()),
            None => Ok(None),
        }
    }

    async fn get_highest_car_position(&self, validator: &ValidatorId) -> Result<Option<u64>> {
        let highest_positions = self.highest_positions.read();
        Ok(highest_positions.get(validator).copied())
    }

    async fn get_cars_range(&self, range: CarRange) -> Result<Vec<Car>> {
        let cars = self.cars.read();
        let mut result: Vec<Car> = cars
            .iter()
            .filter(|((vid, pos), _)| {
                *vid == range.validator_id
                    && *pos >= range.start
                    && range.end.is_none_or(|end| *pos < end)
            })
            .map(|(_, car)| car.clone())
            .collect();

        result.sort_by_key(|c| c.position);
        Ok(result)
    }

    async fn has_car(&self, validator: &ValidatorId, position: u64) -> Result<bool> {
        let cars = self.cars.read();
        Ok(cars.contains_key(&(*validator, position)))
    }

    async fn delete_car(&self, validator: &ValidatorId, position: u64) -> Result<bool> {
        let key = (*validator, position);
        let mut cars = self.cars.write();
        let mut car_index = self.car_index.write();
        let mut highest_positions = self.highest_positions.write();

        if let Some(car) = cars.remove(&key) {
            car_index.remove(&car.hash());

            // Update highest position if we deleted the highest
            if highest_positions.get(validator) == Some(&position) {
                let new_highest = cars
                    .keys()
                    .filter(|(vid, _)| vid == validator)
                    .map(|(_, pos)| *pos)
                    .max();

                match new_highest {
                    Some(pos) => {
                        highest_positions.insert(*validator, pos);
                    }
                    None => {
                        highest_positions.remove(validator);
                    }
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    // ============================================================
    // Attestation Operations
    // ============================================================

    async fn put_attestation(&self, attestation: AggregatedAttestation) -> Result<()> {
        let mut attestations = self.attestations.write();
        attestations.insert(attestation.car_hash, attestation);
        Ok(())
    }

    async fn get_attestation(&self, car_hash: &Hash) -> Result<Option<AggregatedAttestation>> {
        let attestations = self.attestations.read();
        Ok(attestations.get(car_hash).cloned())
    }

    async fn has_attestation(&self, car_hash: &Hash) -> Result<bool> {
        let attestations = self.attestations.read();
        Ok(attestations.contains_key(car_hash))
    }

    async fn delete_attestation(&self, car_hash: &Hash) -> Result<bool> {
        let mut attestations = self.attestations.write();
        Ok(attestations.remove(car_hash).is_some())
    }

    // ============================================================
    // Cut Operations
    // ============================================================

    async fn put_pending_cut(&self, cut: Cut) -> Result<()> {
        let mut pending_cuts = self.pending_cuts.write();
        pending_cuts.insert(cut.height, cut);
        Ok(())
    }

    async fn get_pending_cut(&self, height: u64) -> Result<Option<Cut>> {
        let pending_cuts = self.pending_cuts.read();
        Ok(pending_cuts.get(&height).cloned())
    }

    async fn get_all_pending_cuts(&self) -> Result<Vec<Cut>> {
        let pending_cuts = self.pending_cuts.read();
        Ok(pending_cuts.values().cloned().collect())
    }

    async fn finalize_cut(&self, height: u64) -> Result<Option<Cut>> {
        let mut pending_cuts = self.pending_cuts.write();
        let mut finalized_cuts = self.finalized_cuts.write();

        if let Some(cut) = pending_cuts.remove(&height) {
            finalized_cuts.insert(height, cut.clone());
            Ok(Some(cut))
        } else {
            Ok(None)
        }
    }

    async fn delete_pending_cut(&self, height: u64) -> Result<bool> {
        let mut pending_cuts = self.pending_cuts.write();
        Ok(pending_cuts.remove(&height).is_some())
    }

    async fn put_finalized_cut(&self, cut: Cut) -> Result<()> {
        let mut finalized_cuts = self.finalized_cuts.write();
        finalized_cuts.insert(cut.height, cut);
        Ok(())
    }

    async fn get_finalized_cut(&self, height: u64) -> Result<Option<Cut>> {
        let finalized_cuts = self.finalized_cuts.read();
        Ok(finalized_cuts.get(&height).cloned())
    }

    async fn get_latest_finalized_cut(&self) -> Result<Option<Cut>> {
        let finalized_cuts = self.finalized_cuts.read();
        Ok(finalized_cuts.values().last().cloned())
    }

    async fn get_finalized_cuts_range(&self, range: CutRange) -> Result<Vec<Cut>> {
        let finalized_cuts = self.finalized_cuts.read();
        let result: Vec<Cut> = finalized_cuts
            .range(range.start..)
            .take_while(|(h, _)| range.end.is_none_or(|end| **h < end))
            .map(|(_, cut)| cut.clone())
            .collect();
        Ok(result)
    }

    // ============================================================
    // Garbage Collection
    // ============================================================

    async fn prune_before(&self, height: u64) -> Result<u64> {
        let mut pruned = 0u64;

        // Prune finalized cuts
        {
            let mut finalized_cuts = self.finalized_cuts.write();
            let keys_to_remove: Vec<u64> =
                finalized_cuts.range(..height).map(|(h, _)| *h).collect();

            for key in keys_to_remove {
                finalized_cuts.remove(&key);
                pruned += 1;
            }
        }

        // Note: In a full implementation, we would also prune:
        // - Cars not referenced by retained Cuts
        // - Attestations for pruned Cars
        // - Batches for pruned Cars
        // For MVP, we only prune Cuts

        Ok(pruned)
    }

    async fn stats(&self) -> Result<StorageStats> {
        let batches = self.batches.read();
        let cars = self.cars.read();
        let attestations = self.attestations.read();
        let pending_cuts = self.pending_cuts.read();
        let finalized_cuts = self.finalized_cuts.read();

        Ok(StorageStats {
            batch_count: batches.len() as u64,
            car_count: cars.len() as u64,
            attestation_count: attestations.len() as u64,
            pending_cut_count: pending_cuts.len() as u64,
            finalized_cut_count: finalized_cuts.len() as u64,
            storage_bytes: 0, // In-memory doesn't track this
        })
    }
}

// Note: InMemoryStore implements crate::dcl::DclStore trait above.
// For the data-chain crate's storage traits (BatchStore, CarStore, CutStore),
// create adapters or use the storage crate's DclStore directly.

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_data_chain::BatchDigest;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    fn make_validator_id(id: u8) -> ValidatorId {
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes[0] = id;
        ValidatorId::from_bytes(bytes)
    }

    fn make_test_batch(worker_id: u8) -> Batch {
        Batch::new(
            worker_id,
            vec![Hash::compute(&[worker_id]).as_bytes().to_vec()],
            0,
        )
    }

    fn make_test_car(validator_id: ValidatorId, position: u64) -> Car {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let batch_digest = BatchDigest::new(0, Hash::compute(b"batch"), 10, 100);

        let parent_ref = if position > 0 {
            Some(Hash::compute(&position.to_be_bytes()))
        } else {
            None
        };

        let mut car = Car::new(validator_id, position, vec![batch_digest], parent_ref);
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);
        car
    }

    fn make_test_cut(height: u64) -> Cut {
        Cut::new(height)
    }

    fn make_test_agg_attestation(car: &Car) -> AggregatedAttestation {
        use cipherbft_crypto::BlsKeyPair;
        use cipherbft_data_chain::Attestation;

        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let mut att = Attestation::from_car(car, make_validator_id(0));
        let signing_bytes =
            Attestation::signing_bytes(&att.car_hash, att.car_position, &att.car_proposer);
        att.signature = keypair.sign_attestation(&signing_bytes);
        AggregatedAttestation::aggregate_with_indices(&[(att, 0)], 4).unwrap()
    }

    #[tokio::test]
    async fn test_batch_operations() {
        let store = InMemoryStore::new();

        let batch = make_test_batch(0);
        let hash = batch.hash();

        // Put
        store.put_batch(batch.clone()).await.unwrap();

        // Get
        let retrieved = store.get_batch(&hash).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash(), hash);

        // Has
        assert!(store.has_batch(&hash).await.unwrap());

        // Duplicate should error
        let result = store.put_batch(batch).await;
        assert!(matches!(result, Err(StorageError::DuplicateEntry(_))));

        // Delete
        assert!(store.delete_batch(&hash).await.unwrap());
        assert!(!store.has_batch(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_car_operations() {
        let store = InMemoryStore::new();

        let validator = make_validator_id(1);
        let car = make_test_car(validator, 0);
        let hash = car.hash();

        // Put
        store.put_car(car.clone()).await.unwrap();

        // Get by key
        let retrieved = store.get_car(&validator, 0).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash(), hash);

        // Get by hash
        let retrieved = store.get_car_by_hash(&hash).await.unwrap();
        assert!(retrieved.is_some());

        // Has
        assert!(store.has_car(&validator, 0).await.unwrap());

        // Highest position
        assert_eq!(
            store.get_highest_car_position(&validator).await.unwrap(),
            Some(0)
        );

        // Add another car
        let car2 = make_test_car(validator, 1);
        store.put_car(car2).await.unwrap();
        assert_eq!(
            store.get_highest_car_position(&validator).await.unwrap(),
            Some(1)
        );

        // Range query
        let cars = store
            .get_cars_range(CarRange::all(validator))
            .await
            .unwrap();
        assert_eq!(cars.len(), 2);
        assert_eq!(cars[0].position, 0);
        assert_eq!(cars[1].position, 1);

        // Delete
        assert!(store.delete_car(&validator, 0).await.unwrap());
        assert!(!store.has_car(&validator, 0).await.unwrap());

        // Highest position should update after deletion
        assert_eq!(
            store.get_highest_car_position(&validator).await.unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_attestation_operations() {
        let store = InMemoryStore::new();

        let validator = make_validator_id(1);
        let car = make_test_car(validator, 0);
        let car_hash = car.hash();
        let att = make_test_agg_attestation(&car);

        // Put
        store.put_attestation(att.clone()).await.unwrap();

        // Get
        let retrieved = store.get_attestation(&car_hash).await.unwrap();
        assert!(retrieved.is_some());

        // Has
        assert!(store.has_attestation(&car_hash).await.unwrap());

        // Delete
        assert!(store.delete_attestation(&car_hash).await.unwrap());
        assert!(!store.has_attestation(&car_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_cut_operations() {
        let store = InMemoryStore::new();

        let cut = make_test_cut(1);

        // Put pending
        store.put_pending_cut(cut.clone()).await.unwrap();

        // Get pending
        let retrieved = store.get_pending_cut(1).await.unwrap();
        assert!(retrieved.is_some());

        // Get all pending
        let all_pending = store.get_all_pending_cuts().await.unwrap();
        assert_eq!(all_pending.len(), 1);

        // Finalize
        let finalized = store.finalize_cut(1).await.unwrap();
        assert!(finalized.is_some());

        // Pending should be empty now
        assert!(store.get_pending_cut(1).await.unwrap().is_none());

        // Finalized should have it
        assert!(store.get_finalized_cut(1).await.unwrap().is_some());

        // Latest finalized
        let latest = store.get_latest_finalized_cut().await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().height, 1);
    }

    #[tokio::test]
    async fn test_cut_range_operations() {
        let store = InMemoryStore::new();

        // Add finalized cuts
        for h in 1..=5 {
            store.put_finalized_cut(make_test_cut(h)).await.unwrap();
        }

        // Range query
        let cuts = store
            .get_finalized_cuts_range(CutRange::new(2, Some(4)))
            .await
            .unwrap();
        assert_eq!(cuts.len(), 2);
        assert_eq!(cuts[0].height, 2);
        assert_eq!(cuts[1].height, 3);
    }

    #[tokio::test]
    async fn test_prune() {
        let store = InMemoryStore::new();

        // Add finalized cuts
        for h in 1..=10 {
            store.put_finalized_cut(make_test_cut(h)).await.unwrap();
        }

        // Prune before height 5
        let pruned = store.prune_before(5).await.unwrap();
        assert_eq!(pruned, 4); // heights 1-4

        // Verify remaining
        let cuts = store
            .get_finalized_cuts_range(CutRange::all())
            .await
            .unwrap();
        assert_eq!(cuts.len(), 6); // heights 5-10
        assert_eq!(cuts[0].height, 5);
    }

    #[tokio::test]
    async fn test_stats() {
        let store = InMemoryStore::new();

        // Add some data
        store.put_batch(make_test_batch(0)).await.unwrap();
        store.put_batch(make_test_batch(1)).await.unwrap();

        let validator = make_validator_id(1);
        store.put_car(make_test_car(validator, 0)).await.unwrap();

        store.put_pending_cut(make_test_cut(1)).await.unwrap();
        store.put_finalized_cut(make_test_cut(2)).await.unwrap();

        let stats = store.stats().await.unwrap();
        assert_eq!(stats.batch_count, 2);
        assert_eq!(stats.car_count, 1);
        assert_eq!(stats.pending_cut_count, 1);
        assert_eq!(stats.finalized_cut_count, 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let store = InMemoryStore::new();

        store.put_batch(make_test_batch(0)).await.unwrap();
        store
            .put_car(make_test_car(make_validator_id(1), 0))
            .await
            .unwrap();

        store.clear();

        let stats = store.stats().await.unwrap();
        assert_eq!(stats.batch_count, 0);
        assert_eq!(stats.car_count, 0);
    }
}
