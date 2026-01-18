//! In-memory implementation of DclStore
//!
//! This implementation is primarily for testing and development.
//! It stores all data in memory using concurrent hash maps.
//!
//! # Concurrency Safety
//!
//! This module is designed with the following concurrency guarantees:
//!
//! 1. **Single-Lock Principle**: Related data structures that must be updated
//!    atomically are grouped under a single lock to prevent deadlocks.
//!
//! 2. **Lock Ordering**: When multiple locks must be acquired, they are always
//!    acquired in a consistent order: batches → car_state → attestations →
//!    pending_cuts → finalized_cuts.
//!
//! 3. **Minimal Lock Duration**: Locks are held for the minimum necessary time.
//!    Data is cloned before returning to release locks quickly.
//!
//! # Thread Safety
//!
//! All operations are thread-safe. The `parking_lot::RwLock` is used for
//! efficient read-write locking with reader-writer fairness.

use crate::dcl::{DclStore, StorageStats};
use crate::error::{Result, StorageError};
use crate::tables::CarRange;
use crate::tables::CutRange;
use async_trait::async_trait;
use cipherbft_data_chain::{AggregatedAttestation, Batch, Car, Cut};
use cipherbft_types::{Hash, ValidatorId};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap};

/// Internal state for Car-related data.
///
/// Bundling these together under a single lock eliminates the risk of deadlocks
/// that could occur when acquiring multiple locks in different orders.
struct CarState {
    /// Cars indexed by (ValidatorId, position)
    cars: HashMap<(ValidatorId, u64), Car>,
    /// Car hash to (ValidatorId, position) mapping for reverse lookups
    car_index: HashMap<Hash, (ValidatorId, u64)>,
    /// Highest position for each validator (cached for O(1) lookup)
    highest_positions: HashMap<ValidatorId, u64>,
}

impl CarState {
    fn new() -> Self {
        Self {
            cars: HashMap::new(),
            car_index: HashMap::new(),
            highest_positions: HashMap::new(),
        }
    }

    fn clear(&mut self) {
        self.cars.clear();
        self.car_index.clear();
        self.highest_positions.clear();
    }
}

/// Internal state for Cut-related data.
///
/// Bundling pending and finalized cuts under a single lock ensures atomic
/// transitions during finalization without risk of deadlocks.
struct CutState {
    /// Pending Cuts indexed by height
    pending: BTreeMap<u64, Cut>,
    /// Finalized Cuts indexed by height
    finalized: BTreeMap<u64, Cut>,
}

impl CutState {
    fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            finalized: BTreeMap::new(),
        }
    }

    fn clear(&mut self) {
        self.pending.clear();
        self.finalized.clear();
    }
}

/// In-memory DCL store implementation
///
/// Uses parking_lot RwLock for thread-safe concurrent access with minimal
/// contention. Related data structures are grouped under single locks to
/// prevent deadlocks.
///
/// # Lock Ordering
///
/// If multiple locks must be acquired, they MUST be acquired in this order:
/// 1. `batches`
/// 2. `car_state`
/// 3. `attestations`
/// 4. `cut_state`
///
/// This ordering is enforced by the API design - most operations only need
/// a single lock.
pub struct InMemoryStore {
    /// Batches indexed by hash
    batches: RwLock<HashMap<Hash, Batch>>,

    /// Combined Car state (cars, index, highest positions) under single lock
    /// This eliminates deadlock risk from separate locks on related data
    car_state: RwLock<CarState>,

    /// Aggregated attestations indexed by Car hash
    attestations: RwLock<HashMap<Hash, AggregatedAttestation>>,

    /// Combined Cut state (pending and finalized) under single lock
    /// This enables atomic finalization transitions
    cut_state: RwLock<CutState>,
}

impl InMemoryStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self {
            batches: RwLock::new(HashMap::new()),
            car_state: RwLock::new(CarState::new()),
            attestations: RwLock::new(HashMap::new()),
            cut_state: RwLock::new(CutState::new()),
        }
    }

    /// Clear all data (for testing)
    ///
    /// # Concurrency
    ///
    /// Acquires write locks in the defined ordering to prevent deadlocks.
    pub fn clear(&self) {
        // Acquire locks in defined order: batches → car_state → attestations → cut_state
        let mut batches = self.batches.write();
        let mut car_state = self.car_state.write();
        let mut attestations = self.attestations.write();
        let mut cut_state = self.cut_state.write();

        batches.clear();
        car_state.clear();
        attestations.clear();
        cut_state.clear();
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

        // Single lock acquisition for all car-related state
        let mut state = self.car_state.write();

        if state.cars.contains_key(&key) {
            return Err(StorageError::DuplicateEntry(format!(
                "car {} at position {}",
                car.proposer, car.position
            )));
        }

        // Update highest position if this is higher than current
        let current_highest = state.highest_positions.get(&car.proposer).copied();
        if current_highest.map_or(true, |h| car.position > h) {
            state.highest_positions.insert(car.proposer, car.position);
        }

        state.car_index.insert(hash, key);
        state.cars.insert(key, car);
        Ok(())
    }

    async fn get_car(&self, validator: &ValidatorId, position: u64) -> Result<Option<Car>> {
        let state = self.car_state.read();
        Ok(state.cars.get(&(*validator, position)).cloned())
    }

    async fn get_car_by_hash(&self, hash: &Hash) -> Result<Option<Car>> {
        // Single lock - no risk of deadlock from multiple lock acquisition
        let state = self.car_state.read();

        match state.car_index.get(hash) {
            Some(key) => Ok(state.cars.get(key).cloned()),
            None => Ok(None),
        }
    }

    async fn get_highest_car_position(&self, validator: &ValidatorId) -> Result<Option<u64>> {
        let state = self.car_state.read();
        Ok(state.highest_positions.get(validator).copied())
    }

    async fn get_cars_range(&self, range: CarRange) -> Result<Vec<Car>> {
        let state = self.car_state.read();
        let mut result: Vec<Car> = state
            .cars
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
        let state = self.car_state.read();
        Ok(state.cars.contains_key(&(*validator, position)))
    }

    async fn delete_car(&self, validator: &ValidatorId, position: u64) -> Result<bool> {
        let key = (*validator, position);
        // Single lock acquisition for atomic deletion
        let mut state = self.car_state.write();

        if let Some(car) = state.cars.remove(&key) {
            state.car_index.remove(&car.hash());

            // Update highest position if we deleted the highest
            if state.highest_positions.get(validator) == Some(&position) {
                let new_highest = state
                    .cars
                    .keys()
                    .filter(|(vid, _)| vid == validator)
                    .map(|(_, pos)| *pos)
                    .max();

                match new_highest {
                    Some(pos) => {
                        state.highest_positions.insert(*validator, pos);
                    }
                    None => {
                        state.highest_positions.remove(validator);
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
        let mut state = self.cut_state.write();
        state.pending.insert(cut.height, cut);
        Ok(())
    }

    async fn get_pending_cut(&self, height: u64) -> Result<Option<Cut>> {
        let state = self.cut_state.read();
        Ok(state.pending.get(&height).cloned())
    }

    async fn get_all_pending_cuts(&self) -> Result<Vec<Cut>> {
        let state = self.cut_state.read();
        Ok(state.pending.values().cloned().collect())
    }

    async fn finalize_cut(&self, height: u64) -> Result<Option<Cut>> {
        // Single lock for atomic pending → finalized transition
        // This eliminates the race condition where another thread could
        // see a cut that's neither pending nor finalized
        let mut state = self.cut_state.write();

        if let Some(cut) = state.pending.remove(&height) {
            state.finalized.insert(height, cut.clone());
            Ok(Some(cut))
        } else {
            Ok(None)
        }
    }

    async fn delete_pending_cut(&self, height: u64) -> Result<bool> {
        let mut state = self.cut_state.write();
        Ok(state.pending.remove(&height).is_some())
    }

    async fn put_finalized_cut(&self, cut: Cut) -> Result<()> {
        let mut state = self.cut_state.write();
        state.finalized.insert(cut.height, cut);
        Ok(())
    }

    async fn get_finalized_cut(&self, height: u64) -> Result<Option<Cut>> {
        let state = self.cut_state.read();
        Ok(state.finalized.get(&height).cloned())
    }

    async fn get_latest_finalized_cut(&self) -> Result<Option<Cut>> {
        let state = self.cut_state.read();
        Ok(state.finalized.values().last().cloned())
    }

    async fn get_finalized_cuts_range(&self, range: CutRange) -> Result<Vec<Cut>> {
        let state = self.cut_state.read();
        let result: Vec<Cut> = state
            .finalized
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

        // Step 1: Collect Car hashes referenced by Cuts we're keeping
        let mut referenced_car_hashes = std::collections::HashSet::new();
        {
            let state = self.cut_state.read();
            // Collect from retained finalized cuts (height >= prune_height)
            for (_, cut) in state.finalized.range(height..) {
                for car in cut.cars.values() {
                    referenced_car_hashes.insert(car.hash());
                }
            }
            // Also keep references from pending cuts
            for cut in state.pending.values() {
                for car in cut.cars.values() {
                    referenced_car_hashes.insert(car.hash());
                }
            }
        }

        // Step 2: Prune finalized cuts
        {
            let mut state = self.cut_state.write();
            let keys_to_remove: Vec<u64> =
                state.finalized.range(..height).map(|(h, _)| *h).collect();

            for key in keys_to_remove {
                state.finalized.remove(&key);
                pruned += 1;
            }
        }

        // Step 3: Collect batch hashes referenced by retained Cars
        let mut referenced_batch_hashes = std::collections::HashSet::new();
        {
            let state = self.car_state.read();
            for car in state.cars.values() {
                let car_hash = car.hash();
                if referenced_car_hashes.contains(&car_hash) {
                    // This car is referenced, keep its batches
                    for batch_digest in &car.batch_digests {
                        referenced_batch_hashes.insert(batch_digest.digest);
                    }
                }
            }
        }

        // Step 4: Prune unreferenced Cars and their indices
        {
            let mut state = self.car_state.write();
            let cars_to_remove: Vec<(ValidatorId, u64)> = state
                .cars
                .iter()
                .filter_map(|(key, car)| {
                    let car_hash = car.hash();
                    if !referenced_car_hashes.contains(&car_hash) {
                        Some(*key)
                    } else {
                        None
                    }
                })
                .collect();

            for (validator, position) in cars_to_remove {
                if let Some(car) = state.cars.remove(&(validator, position)) {
                    state.car_index.remove(&car.hash());
                    pruned += 1;

                    // Update highest position if necessary
                    if state.highest_positions.get(&validator) == Some(&position) {
                        let new_highest = state
                            .cars
                            .keys()
                            .filter(|(vid, _)| *vid == validator)
                            .map(|(_, pos)| *pos)
                            .max();

                        match new_highest {
                            Some(pos) => {
                                state.highest_positions.insert(validator, pos);
                            }
                            None => {
                                state.highest_positions.remove(&validator);
                            }
                        }
                    }
                }
            }
        }

        // Step 5: Prune unreferenced attestations
        {
            let mut attestations = self.attestations.write();
            let atts_to_remove: Vec<Hash> = attestations
                .keys()
                .filter(|hash| !referenced_car_hashes.contains(hash))
                .copied()
                .collect();

            for hash in atts_to_remove {
                attestations.remove(&hash);
                pruned += 1;
            }
        }

        // Step 6: Prune unreferenced batches
        {
            let mut batches = self.batches.write();
            let batches_to_remove: Vec<Hash> = batches
                .keys()
                .filter(|hash| !referenced_batch_hashes.contains(hash))
                .copied()
                .collect();

            for hash in batches_to_remove {
                batches.remove(&hash);
                pruned += 1;
            }
        }

        Ok(pruned)
    }

    async fn stats(&self) -> Result<StorageStats> {
        // Acquire locks in documented order to prevent deadlocks
        let batches = self.batches.read();
        let car_state = self.car_state.read();
        let attestations = self.attestations.read();
        let cut_state = self.cut_state.read();

        Ok(StorageStats {
            batch_count: batches.len() as u64,
            car_count: car_state.cars.len() as u64,
            attestation_count: attestations.len() as u64,
            pending_cut_count: cut_state.pending.len() as u64,
            finalized_cut_count: cut_state.finalized.len() as u64,
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
