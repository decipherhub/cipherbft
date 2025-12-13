//! Primary process state management

use crate::attestation::Attestation;
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

/// Primary process state
#[derive(Debug)]
pub struct PrimaryState {
    /// Our validator identity
    pub our_id: ValidatorId,
    /// Current consensus height
    pub current_height: u64,
    /// Pending batch digests from Workers (to be included in next Car)
    pub pending_digests: Vec<BatchDigest>,
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
    /// Highest attested Car per validator (ready for Cut inclusion)
    pub attested_cars: HashMap<ValidatorId, (Car, Vec<Attestation>)>,
    /// Last attested validator index (for round-robin fairness)
    pub last_attested_idx: usize,
    /// Known equivocations (validator -> position -> multiple car hashes)
    pub equivocations: HashMap<ValidatorId, HashMap<u64, Vec<Hash>>>,
}

impl PrimaryState {
    /// Create new state for a validator
    pub fn new(our_id: ValidatorId) -> Self {
        Self {
            our_id,
            current_height: 0,
            pending_digests: Vec::new(),
            our_position: 0,
            last_car_hash: None,
            empty_car_count: 0,
            last_seen_positions: HashMap::new(),
            last_seen_car_hashes: HashMap::new(),
            pending_cars: HashMap::new(),
            attested_cars: HashMap::new(),
            last_attested_idx: 0,
            equivocations: HashMap::new(),
        }
    }

    /// Add batch digest from Worker
    pub fn add_batch_digest(&mut self, digest: BatchDigest) {
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
    pub fn mark_attested(&mut self, car: Car, attestations: Vec<Attestation>) {
        let validator = car.proposer;
        self.attested_cars.insert(validator, (car, attestations));
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_car_tracking() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; 32]));

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
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; 32]));
        let validator = ValidatorId::from_bytes([2u8; 32]);

        // Expected position for unknown validator is 0
        assert_eq!(state.expected_position(&validator), 0);

        // Update and check
        state.update_last_seen(validator, 5, Hash::compute(b"car5"));
        assert_eq!(state.expected_position(&validator), 6);
    }

    #[test]
    fn test_equivocation_detection() {
        let mut state = PrimaryState::new(ValidatorId::from_bytes([1u8; 32]));
        let validator = ValidatorId::from_bytes([2u8; 32]);

        // First car at position 5
        state.record_equivocation(validator, 5, Hash::compute(b"car5a"));
        assert!(!state.has_equivocated(&validator, 5));

        // Second car at same position = equivocation
        state.record_equivocation(validator, 5, Hash::compute(b"car5b"));
        assert!(state.has_equivocated(&validator, 5));

        // Different position is fine
        assert!(!state.has_equivocated(&validator, 6));
    }
}
