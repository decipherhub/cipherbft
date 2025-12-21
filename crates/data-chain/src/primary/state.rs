//! Primary process state management

use crate::attestation::{AggregatedAttestation, Attestation};
use crate::batch::BatchDigest;
use crate::car::Car;
use cipherbft_types::{Hash, ValidatorId};
use std::collections::HashMap;
use std::time::Instant;

/// Pending Car awaiting attestations
#[derive(Clone, Debug)]
pub struct PendingCar {
    /// The Car itself
    pub car: Car,
    /// When the Car was created
    pub created_at: Instant,
    /// Attestations received so far
    pub attestations: Vec<Attestation>,
    /// Current backoff multiplier for timeout
    pub backoff_multiplier: u32,
}

impl PendingCar {
    /// Create a new pending car
    pub fn new(car: Car) -> Self {
        Self {
            car,
            created_at: Instant::now(),
            attestations: Vec::new(),
            backoff_multiplier: 1,
        }
    }

    /// Add an attestation
    pub fn add_attestation(&mut self, attestation: Attestation) {
        self.attestations.push(attestation);
    }

    /// Get attestation count
    pub fn attestation_count(&self) -> usize {
        // +1 for self-attestation (implicit)
        self.attestations.len() + 1
    }
}

/// Car awaiting batch synchronization
#[derive(Clone, Debug)]
pub struct CarAwaitingBatches {
    /// The Car that needs batches
    pub car: Car,
    /// Missing batch digests
    pub missing_digests: Vec<Hash>,
    /// When the sync request was made
    pub requested_at: Instant,
}

/// Pipeline stage for tracking consensus progress (T111)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    /// Collecting attestations for current height
    Collecting,
    /// Cut formed, awaiting consensus decision
    Proposing,
    /// Consensus timeout, preserving attestations
    TimedOut,
}

/// Primary process state
#[derive(Debug)]
pub struct PrimaryState {
    /// Our validator identity
    pub our_id: ValidatorId,
    /// Current consensus height
    pub current_height: u64,
    /// Pending batch digests from Workers (to be included in next Car)
    pub pending_digests: Vec<BatchDigest>,
    /// Available batch digests we've received from Workers
    pub available_batches: std::collections::HashSet<Hash>,
    /// Last Car position we created
    pub our_position: u64,
    /// Hash of our last created Car (for parent_ref)
    pub last_car_hash: Option<Hash>,
    /// Consecutive empty Car count
    pub empty_car_count: u32,
    /// Last seen position per validator (for position validation)
    pub last_seen_positions: HashMap<ValidatorId, u64>,
    /// Last seen Car hash per validator (for parent_ref validation)
    pub last_seen_car_hashes: HashMap<ValidatorId, Hash>,
    /// Pending Cars awaiting attestations (keyed by Car hash)
    pub pending_cars: HashMap<Hash, PendingCar>,
    /// Cars awaiting batch synchronization (keyed by Car hash)
    pub cars_awaiting_batches: HashMap<Hash, CarAwaitingBatches>,
    /// Highest attested Car per validator (ready for Cut inclusion)
    /// Stores the Car and its aggregated attestation (with aggregated BLS signature)
    pub attested_cars: HashMap<ValidatorId, (Car, AggregatedAttestation)>,
    /// Last attested validator index (for round-robin fairness)
    pub last_attested_idx: usize,
    /// Known equivocations (validator -> position -> multiple car hashes)
    pub equivocations: HashMap<ValidatorId, HashMap<u64, Vec<Hash>>>,

    // =========================================================
    // Pipeline state tracking (T111)
    // =========================================================
    /// Current pipeline stage
    pub pipeline_stage: PipelineStage,
    /// Next height attestations (received before current height is decided)
    /// Map of height -> (Car hash -> attestations)
    pub next_height_attestations: HashMap<u64, HashMap<Hash, Vec<Attestation>>>,
    /// Preserved attested Cars from timed-out rounds (T113)
    /// These should be included in the next Cut attempt
    pub preserved_attested_cars: HashMap<ValidatorId, (Car, AggregatedAttestation)>,
    /// Last finalized height
    pub last_finalized_height: u64,
}

impl PrimaryState {
    /// Create new state for a validator
    pub fn new(our_id: ValidatorId) -> Self {
        Self {
            our_id,
            current_height: 0,
            pending_digests: Vec::new(),
            available_batches: std::collections::HashSet::new(),
            our_position: 0,
            last_car_hash: None,
            empty_car_count: 0,
            last_seen_positions: HashMap::new(),
            last_seen_car_hashes: HashMap::new(),
            pending_cars: HashMap::new(),
            cars_awaiting_batches: HashMap::new(),
            attested_cars: HashMap::new(),
            last_attested_idx: 0,
            equivocations: HashMap::new(),
            // Pipeline state (T111)
            pipeline_stage: PipelineStage::Collecting,
            next_height_attestations: HashMap::new(),
            preserved_attested_cars: HashMap::new(),
            last_finalized_height: 0,
        }
    }

    /// Add batch digest from Worker
    pub fn add_batch_digest(&mut self, digest: BatchDigest) {
        // Track as available for batch availability checking
        self.available_batches.insert(digest.digest);
        self.pending_digests.push(digest);
    }

    /// Take pending digests (clears the pending list)
    pub fn take_pending_digests(&mut self) -> Vec<BatchDigest> {
        std::mem::take(&mut self.pending_digests)
    }

    /// Update our position after creating a Car
    pub fn update_our_position(&mut self, position: u64, car_hash: Hash, is_empty: bool) {
        self.our_position = position;
        self.last_car_hash = Some(car_hash);

        if is_empty {
            self.empty_car_count += 1;
        } else {
            self.empty_car_count = 0;
        }
    }

    /// Check if we can create another empty Car
    pub fn can_create_empty_car(&self, max_empty: u32) -> bool {
        self.empty_car_count < max_empty
    }

    /// Get expected position for a validator's next Car
    pub fn expected_position(&self, validator: &ValidatorId) -> u64 {
        self.last_seen_positions
            .get(validator)
            .map(|p| p + 1)
            .unwrap_or(0)
    }

    /// Update last seen position for a validator
    pub fn update_last_seen(&mut self, validator: ValidatorId, position: u64, car_hash: Hash) {
        self.last_seen_positions.insert(validator, position);
        self.last_seen_car_hashes.insert(validator, car_hash);
    }

    /// Get last seen Car hash for parent_ref validation
    pub fn last_seen_car_hash(&self, validator: &ValidatorId) -> Option<&Hash> {
        self.last_seen_car_hashes.get(validator)
    }

    /// Add pending Car
    pub fn add_pending_car(&mut self, car: Car) {
        let hash = car.hash();
        self.pending_cars.insert(hash, PendingCar::new(car));
    }

    /// Get pending Car by hash
    pub fn get_pending_car(&self, hash: &Hash) -> Option<&PendingCar> {
        self.pending_cars.get(hash)
    }

    /// Get mutable pending Car by hash
    pub fn get_pending_car_mut(&mut self, hash: &Hash) -> Option<&mut PendingCar> {
        self.pending_cars.get_mut(hash)
    }

    /// Remove pending Car (when attested or timed out)
    pub fn remove_pending_car(&mut self, hash: &Hash) -> Option<PendingCar> {
        self.pending_cars.remove(hash)
    }

    /// Mark Car as attested (move from pending to attested)
    ///
    /// # Arguments
    /// * `car` - The Car that has been attested
    /// * `aggregated` - The aggregated attestation with BLS aggregate signature
    pub fn mark_attested(&mut self, car: Car, aggregated: AggregatedAttestation) {
        let validator = car.proposer;
        self.attested_cars.insert(validator, (car, aggregated));
    }

    /// Get attested cars for Cut formation
    ///
    /// Returns a reference to the map of validator -> (Car, AggregatedAttestation)
    pub fn get_attested_cars(&self) -> &HashMap<ValidatorId, (Car, AggregatedAttestation)> {
        &self.attested_cars
    }

    /// Record equivocation evidence
    pub fn record_equivocation(&mut self, validator: ValidatorId, position: u64, car_hash: Hash) {
        self.equivocations
            .entry(validator)
            .or_default()
            .entry(position)
            .or_default()
            .push(car_hash);
    }

    /// Check if validator has equivocated at position
    pub fn has_equivocated(&self, validator: &ValidatorId, position: u64) -> bool {
        self.equivocations
            .get(validator)
            .and_then(|positions| positions.get(&position))
            .map(|hashes| hashes.len() > 1)
            .unwrap_or(false)
    }

    /// Get validators with attested Cars (for Cut formation)
    pub fn validators_with_attested_cars(&self) -> Vec<ValidatorId> {
        self.attested_cars.keys().cloned().collect()
    }

    /// Clear state for new height
    pub fn advance_height(&mut self, new_height: u64) {
        self.current_height = new_height;
        self.pending_cars.clear();
        // Keep attested_cars as they may be used in the new height's Cut
    }

    // =========================================================
    // Batch availability checking (T097)
    // =========================================================

    /// Check if we have all batch data for a Car
    ///
    /// Returns (has_all, missing_digests)
    pub fn check_batch_availability(&self, car: &Car) -> (bool, Vec<Hash>) {
        let mut missing = Vec::new();
        for batch_digest in &car.batch_digests {
            if !self.available_batches.contains(&batch_digest.digest) {
                missing.push(batch_digest.digest);
            }
        }
        (missing.is_empty(), missing)
    }

    /// Mark a batch as available (when synced from peer)
    pub fn mark_batch_available(&mut self, digest: Hash) {
        self.available_batches.insert(digest);
    }

    /// Check if a batch is available
    pub fn has_batch(&self, digest: &Hash) -> bool {
        self.available_batches.contains(digest)
    }

    // =========================================================
    // Cars awaiting batches (T098)
    // =========================================================

    /// Add Car to awaiting batches queue
    pub fn add_car_awaiting_batches(&mut self, car: Car, missing_digests: Vec<Hash>) {
        let car_hash = car.hash();
        self.cars_awaiting_batches.insert(
            car_hash,
            CarAwaitingBatches {
                car,
                missing_digests,
                requested_at: Instant::now(),
            },
        );
    }

    /// Get Cars that are ready (all batches now available)
    ///
    /// Returns Cars that can now be processed
    pub fn get_ready_cars(&mut self) -> Vec<Car> {
        let mut ready = Vec::new();
        let mut ready_hashes = Vec::new();

        for (hash, awaiting) in &self.cars_awaiting_batches {
            let (has_all, _) = self.check_batch_availability(&awaiting.car);
            if has_all {
                ready.push(awaiting.car.clone());
                ready_hashes.push(*hash);
            }
        }

        // Remove ready cars from waiting
        for hash in ready_hashes {
            self.cars_awaiting_batches.remove(&hash);
        }

        ready
    }

    /// Check if a Car is already waiting for batches
    pub fn is_awaiting_batches(&self, car_hash: &Hash) -> bool {
        self.cars_awaiting_batches.contains_key(car_hash)
    }

    // =========================================================
    // Pipeline state management (T111-T113)
    // =========================================================

    /// Set pipeline stage (T111)
    pub fn set_pipeline_stage(&mut self, stage: PipelineStage) {
        self.pipeline_stage = stage;
    }

    /// Store attestation for a future height (T112)
    ///
    /// When we receive attestations for height > current_height,
    /// we store them for later use.
    pub fn store_next_height_attestation(&mut self, height: u64, attestation: Attestation) {
        let car_hash = attestation.car_hash;
        self.next_height_attestations
            .entry(height)
            .or_default()
            .entry(car_hash)
            .or_default()
            .push(attestation);
    }

    /// Get and clear attestations for a specific height (T112)
    ///
    /// Called when advancing to a new height to process pre-received attestations.
    pub fn take_next_height_attestations(
        &mut self,
        height: u64,
    ) -> HashMap<Hash, Vec<Attestation>> {
        self.next_height_attestations
            .remove(&height)
            .unwrap_or_default()
    }

    /// Preserve current attested Cars on consensus timeout (T113)
    ///
    /// When a consensus round times out, we preserve attested Cars
    /// so they can be included in the next Cut attempt.
    pub fn preserve_attested_cars_on_timeout(&mut self) {
        // Merge current attested cars into preserved
        // Newer attestations (higher positions) take precedence
        for (validator, (car, attestation)) in std::mem::take(&mut self.attested_cars) {
            let should_update = self
                .preserved_attested_cars
                .get(&validator)
                .map(|(existing, _)| car.position > existing.position)
                .unwrap_or(true);

            if should_update {
                self.preserved_attested_cars
                    .insert(validator, (car, attestation));
            }
        }
        self.pipeline_stage = PipelineStage::TimedOut;
    }

    /// Restore preserved attested Cars into current state (T113)
    ///
    /// Called when starting a new round to include preserved Cars.
    pub fn restore_preserved_attested_cars(&mut self) {
        // Move preserved into current attested_cars
        for (validator, (car, attestation)) in std::mem::take(&mut self.preserved_attested_cars) {
            let should_update = self
                .attested_cars
                .get(&validator)
                .map(|(existing, _)| car.position > existing.position)
                .unwrap_or(true);

            if should_update {
                self.attested_cars.insert(validator, (car, attestation));
            }
        }
        self.pipeline_stage = PipelineStage::Collecting;
    }

    /// Finalize a height (T111)
    ///
    /// Called when consensus decides on a Cut.
    pub fn finalize_height(&mut self, height: u64) {
        self.last_finalized_height = height;
        self.current_height = height + 1;
        self.pipeline_stage = PipelineStage::Collecting;

        // Clear preserved cars since consensus succeeded
        self.preserved_attested_cars.clear();

        // Clear old next-height attestations (anything before new current height)
        self.next_height_attestations
            .retain(|h, _| *h >= self.current_height);
    }

    /// Get combined attested Cars (current + preserved) for Cut formation
    pub fn get_all_attested_cars(&self) -> HashMap<ValidatorId, (Car, AggregatedAttestation)> {
        let mut combined = self.preserved_attested_cars.clone();

        // Current attested cars take precedence (might have newer positions)
        for (validator, (car, attestation)) in &self.attested_cars {
            let should_update = combined
                .get(validator)
                .map(|(existing, _)| car.position > existing.position)
                .unwrap_or(true);

            if should_update {
                combined.insert(*validator, (car.clone(), attestation.clone()));
            }
        }

        combined
    }

    /// Check if we have pending next-height attestations
    pub fn has_pending_next_height_attestations(&self) -> bool {
        !self.next_height_attestations.is_empty()
    }

    /// Get pipeline state summary for diagnostics
    pub fn pipeline_summary(&self) -> PipelineSummary {
        PipelineSummary {
            current_height: self.current_height,
            last_finalized_height: self.last_finalized_height,
            stage: self.pipeline_stage,
            attested_car_count: self.attested_cars.len(),
            preserved_car_count: self.preserved_attested_cars.len(),
            next_height_attestation_count: self.next_height_attestations.len(),
        }
    }
}

/// Summary of pipeline state for diagnostics (T111)
#[derive(Debug, Clone)]
pub struct PipelineSummary {
    pub current_height: u64,
    pub last_finalized_height: u64,
    pub stage: PipelineStage,
    pub attested_car_count: usize,
    pub preserved_car_count: usize,
    pub next_height_attestation_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    /// Create a dummy signature for testing
    fn dummy_signature() -> cipherbft_crypto::BlsSignature {
        let kp = cipherbft_crypto::BlsKeyPair::generate(&mut rand::thread_rng());
        kp.sign_attestation(b"dummy")
    }

    /// Create a dummy aggregate signature for testing
    fn dummy_aggregate_signature() -> cipherbft_crypto::BlsAggregateSignature {
        let sig = dummy_signature();
        cipherbft_crypto::BlsAggregateSignature::from_signature(&sig)
    }

    #[test]
    fn test_empty_car_tracking() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]));

        // Initially can create empty cars
        assert!(state.can_create_empty_car(3));

        // After 3 empty cars, should not be able to create more
        state.update_our_position(0, Hash::compute(b"car0"), true);
        assert!(state.can_create_empty_car(3));
        state.update_our_position(1, Hash::compute(b"car1"), true);
        assert!(state.can_create_empty_car(3));
        state.update_our_position(2, Hash::compute(b"car2"), true);
        assert!(!state.can_create_empty_car(3));

        // Non-empty car resets counter
        state.update_our_position(3, Hash::compute(b"car3"), false);
        assert!(state.can_create_empty_car(3));
        assert_eq!(state.empty_car_count, 0);
    }

    #[test]
    fn test_position_tracking() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]));
        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Expected position for unknown validator is 0
        assert_eq!(state.expected_position(&validator), 0);

        // Update and check
        state.update_last_seen(validator, 5, Hash::compute(b"car5"));
        assert_eq!(state.expected_position(&validator), 6);
    }

    #[test]
    fn test_equivocation_detection() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]));
        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // First car at position 5
        state.record_equivocation(validator, 5, Hash::compute(b"car5a"));
        assert!(!state.has_equivocated(&validator, 5));

        // Second car at same position = equivocation
        state.record_equivocation(validator, 5, Hash::compute(b"car5b"));
        assert!(state.has_equivocated(&validator, 5));

        // Different position is fine
        assert!(!state.has_equivocated(&validator, 6));
    }

    // =========================================================
    // Pipeline State Tests (T117)
    // =========================================================

    #[test]
    fn test_pipeline_stage_transitions() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]));

        // Initially in Collecting stage
        assert_eq!(state.pipeline_stage, PipelineStage::Collecting);

        // Transition to Proposing
        state.set_pipeline_stage(PipelineStage::Proposing);
        assert_eq!(state.pipeline_stage, PipelineStage::Proposing);

        // Timeout preserves attestations
        state.preserve_attested_cars_on_timeout();
        assert_eq!(state.pipeline_stage, PipelineStage::TimedOut);

        // Restore moves back to Collecting
        state.restore_preserved_attested_cars();
        assert_eq!(state.pipeline_stage, PipelineStage::Collecting);
    }

    #[test]
    fn test_preserve_attested_cars_on_timeout() {
        use crate::car::Car;
        use bitvec::prelude::*;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id);

        let validator1 = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        let validator2 = ValidatorId::from_bytes([3u8; VALIDATOR_ID_SIZE]);

        // Add attested cars
        let car1 = Car::new(validator1, 5, vec![], None);
        let car2 = Car::new(validator2, 3, vec![], None);

        let mut bv = bitvec![u8, Lsb0; 0; 4];
        bv.set(0, true);
        bv.set(1, true);

        let agg1 = AggregatedAttestation {
            car_hash: car1.hash(),
            car_position: car1.position,
            car_proposer: car1.proposer,
            validators: bv.clone(),
            aggregated_signature: dummy_aggregate_signature(),
        };
        let agg2 = AggregatedAttestation {
            car_hash: car2.hash(),
            car_position: car2.position,
            car_proposer: car2.proposer,
            validators: bv,
            aggregated_signature: dummy_aggregate_signature(),
        };

        state.mark_attested(car1.clone(), agg1.clone());
        state.mark_attested(car2.clone(), agg2.clone());

        assert_eq!(state.attested_cars.len(), 2);
        assert_eq!(state.preserved_attested_cars.len(), 0);

        // Timeout preserves cars
        state.preserve_attested_cars_on_timeout();

        assert_eq!(state.attested_cars.len(), 0);
        assert_eq!(state.preserved_attested_cars.len(), 2);

        // Restore moves them back
        state.restore_preserved_attested_cars();

        assert_eq!(state.attested_cars.len(), 2);
        assert_eq!(state.preserved_attested_cars.len(), 0);
    }

    #[test]
    fn test_next_height_attestations() {
        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id);
        state.current_height = 5;

        let attester = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);
        let car_hash = Hash::compute(b"car_for_height_6");

        // Create attestation for future height
        let attestation = Attestation {
            car_hash,
            car_position: 0,
            car_proposer: attester,
            attester,
            signature: dummy_signature(),
        };

        // Store for height 6 (next height)
        state.store_next_height_attestation(6, attestation.clone());

        assert!(state.has_pending_next_height_attestations());

        // Take attestations when we reach height 6
        let next_atts = state.take_next_height_attestations(6);
        assert_eq!(next_atts.len(), 1);
        assert!(next_atts.contains_key(&car_hash));
        assert_eq!(next_atts.get(&car_hash).unwrap().len(), 1);

        // Should be empty now
        assert!(!state.has_pending_next_height_attestations());
    }

    #[test]
    fn test_finalize_height() {
        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id);
        state.current_height = 5;

        // Store some next-height attestations
        let attestation = Attestation {
            car_hash: Hash::compute(b"car"),
            car_position: 0,
            car_proposer: our_id,
            attester: our_id,
            signature: dummy_signature(),
        };
        state.store_next_height_attestation(4, attestation.clone()); // Old - should be cleared
        state.store_next_height_attestation(6, attestation.clone()); // Future - should be kept

        // Finalize height 5
        state.finalize_height(5);

        assert_eq!(state.last_finalized_height, 5);
        assert_eq!(state.current_height, 6);
        assert_eq!(state.pipeline_stage, PipelineStage::Collecting);

        // Old attestations should be cleared, future ones kept
        assert_eq!(state.next_height_attestations.len(), 1);
        assert!(state.next_height_attestations.contains_key(&6));
    }

    #[test]
    fn test_get_all_attested_cars_merges_preserved() {
        use crate::car::Car;
        use bitvec::prelude::*;

        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id);

        let validator = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        // Create preserved car at position 3
        let car_old = Car::new(validator, 3, vec![], None);
        let mut bv = bitvec![u8, Lsb0; 0; 4];
        bv.set(0, true);
        bv.set(1, true);
        let agg_old = AggregatedAttestation {
            car_hash: car_old.hash(),
            car_position: car_old.position,
            car_proposer: car_old.proposer,
            validators: bv.clone(),
            aggregated_signature: dummy_aggregate_signature(),
        };
        state
            .preserved_attested_cars
            .insert(validator, (car_old.clone(), agg_old));

        // Create current car at position 5 (newer)
        let car_new = Car::new(validator, 5, vec![], None);
        let agg_new = AggregatedAttestation {
            car_hash: car_new.hash(),
            car_position: car_new.position,
            car_proposer: car_new.proposer,
            validators: bv,
            aggregated_signature: dummy_aggregate_signature(),
        };
        state
            .attested_cars
            .insert(validator, (car_new.clone(), agg_new));

        // Get all should return the newer one
        let all = state.get_all_attested_cars();
        assert_eq!(all.len(), 1);
        assert_eq!(all.get(&validator).unwrap().0.position, 5);
    }

    #[test]
    fn test_pipeline_summary() {
        let our_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);
        let mut state = PrimaryState::new(our_id);
        state.current_height = 10;
        state.last_finalized_height = 9;

        let summary = state.pipeline_summary();
        assert_eq!(summary.current_height, 10);
        assert_eq!(summary.last_finalized_height, 9);
        assert_eq!(summary.stage, PipelineStage::Collecting);
        assert_eq!(summary.attested_car_count, 0);
        assert_eq!(summary.preserved_car_count, 0);
        assert_eq!(summary.next_height_attestation_count, 0);
    }
}
