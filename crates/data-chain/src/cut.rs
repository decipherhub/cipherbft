//! Cut type for DCL consensus proposals
//!
//! A Cut is a snapshot of highest attested Cars for consensus.
//! It represents the data that will be finalized in a block.

use crate::attestation::AggregatedAttestation;
use crate::car::Car;
use cipherbft_crypto::BlsPublicKey;
use cipherbft_types::{Hash, ValidatorId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A Cut is a snapshot of highest attested Cars for consensus
///
/// Properties:
/// - Each validator has at most one Car in the Cut
/// - All Cars must have f+1 attestations
/// - Cars are processed in ValidatorId ascending order for determinism
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Cut {
    /// Consensus height for this Cut
    pub height: u64,
    /// Map of validator to their highest attested Car
    pub cars: HashMap<ValidatorId, Car>,
    /// Aggregated attestations for each Car (keyed by Car hash)
    pub attestations: HashMap<Hash, AggregatedAttestation>,
}

impl Cut {
    /// Create a new empty Cut for a given height
    pub fn new(height: u64) -> Self {
        Self {
            height,
            cars: HashMap::new(),
            attestations: HashMap::new(),
        }
    }

    /// Add a Car with its attestation to the Cut
    pub fn add_car(&mut self, car: Car, attestation: AggregatedAttestation) {
        let car_hash = car.hash();
        self.cars.insert(car.proposer, car);
        self.attestations.insert(car_hash, attestation);
    }

    /// Iterate Cars in deterministic order (ValidatorId ascending)
    ///
    /// This ensures all validators process transactions in the same order
    /// for deterministic deduplication.
    pub fn ordered_cars(&self) -> impl Iterator<Item = (&ValidatorId, &Car)> {
        let mut entries: Vec<_> = self.cars.iter().collect();
        entries.sort_by_key(|(vid, _)| *vid);
        entries.into_iter()
    }

    /// Get Cars as ordered Vec (for serialization)
    pub fn ordered_cars_vec(&self) -> Vec<(&ValidatorId, &Car)> {
        self.ordered_cars().collect()
    }

    /// Total transaction count across all Cars
    pub fn total_tx_count(&self) -> u32 {
        self.cars.values().map(|car| car.tx_count()).sum()
    }

    /// Total byte size across all Cars
    pub fn total_bytes(&self) -> u32 {
        self.cars.values().map(|car| car.total_bytes()).sum()
    }

    /// Number of validators included in this Cut
    pub fn validator_count(&self) -> usize {
        self.cars.len()
    }

    /// Check if a validator is included in the Cut
    pub fn contains_validator(&self, validator: &ValidatorId) -> bool {
        self.cars.contains_key(validator)
    }

    /// Get Car for a specific validator
    pub fn get_car(&self, validator: &ValidatorId) -> Option<&Car> {
        self.cars.get(validator)
    }

    /// Get attestation for a Car hash
    pub fn get_attestation(&self, car_hash: &Hash) -> Option<&AggregatedAttestation> {
        self.attestations.get(car_hash)
    }

    /// Verify all attestations meet threshold and signatures are valid
    ///
    /// # Arguments
    /// * `threshold` - Required attestation count (f+1)
    /// * `get_pubkey` - Function to get public key by validator index
    pub fn verify<F>(&self, threshold: usize, get_pubkey: F) -> bool
    where
        F: Fn(usize) -> Option<BlsPublicKey>,
    {
        for (_, car) in &self.cars {
            let car_hash = car.hash();

            // Get attestation for this Car
            let Some(agg_att) = self.attestations.get(&car_hash) else {
                return false;
            };

            // Check threshold
            if agg_att.count() < threshold {
                return false;
            }

            // Verify aggregated signature
            if !agg_att.verify(&get_pubkey) {
                return false;
            }
        }

        true
    }

    /// Check monotonicity against last finalized Cut
    ///
    /// Each validator's Car position must be >= their position in the last Cut
    pub fn is_monotonic(&self, last_cut: &Cut) -> bool {
        for (validator, car) in &self.cars {
            if let Some(last_car) = last_cut.cars.get(validator) {
                if car.position < last_car.position {
                    return false;
                }
            }
        }
        true
    }

    /// Check anti-censorship rule
    ///
    /// Returns true if at most f validators with available attested Cars are excluded
    pub fn check_anti_censorship(
        &self,
        available_validators: &[ValidatorId],
        max_excluded: usize,
    ) -> bool {
        let excluded_count = available_validators
            .iter()
            .filter(|v| !self.cars.contains_key(v))
            .count();

        excluded_count <= max_excluded
    }

    /// Get validators not included in this Cut
    pub fn excluded_validators(&self, all_validators: &[ValidatorId]) -> Vec<ValidatorId> {
        all_validators
            .iter()
            .filter(|v| !self.cars.contains_key(v))
            .cloned()
            .collect()
    }

    /// Merge another Cut into this one (for testing/building)
    pub fn merge(&mut self, other: Cut) {
        for (validator, car) in other.cars {
            self.cars.insert(validator, car);
        }
        for (hash, att) in other.attestations {
            self.attestations.insert(hash, att);
        }
    }

    /// Check if Cut is empty
    pub fn is_empty(&self) -> bool {
        self.cars.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::BatchDigest;
    use cipherbft_crypto::BlsKeyPair;

    fn make_test_car(keypair: &BlsKeyPair, position: u64) -> Car {
        let validator_id = ValidatorId::from_bytes(keypair.public_key.hash());
        let mut car = Car::new(validator_id, position, vec![], None);
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);
        car
    }

    #[test]
    fn test_ordered_cars() {
        let kp1 = BlsKeyPair::generate(&mut rand::thread_rng());
        let kp2 = BlsKeyPair::generate(&mut rand::thread_rng());
        let kp3 = BlsKeyPair::generate(&mut rand::thread_rng());

        let car1 = make_test_car(&kp1, 0);
        let car2 = make_test_car(&kp2, 0);
        let car3 = make_test_car(&kp3, 0);

        let mut cut = Cut::new(1);
        cut.cars.insert(car1.proposer, car1.clone());
        cut.cars.insert(car2.proposer, car2.clone());
        cut.cars.insert(car3.proposer, car3.clone());

        // ordered_cars should return in ValidatorId order
        let ordered: Vec<_> = cut.ordered_cars().collect();
        assert_eq!(ordered.len(), 3);

        // Verify ordering
        for i in 0..ordered.len() - 1 {
            assert!(ordered[i].0 < ordered[i + 1].0);
        }
    }

    #[test]
    fn test_monotonicity() {
        let kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let validator_id = ValidatorId::from_bytes(kp.public_key.hash());

        let car_pos_5 = Car::new(validator_id, 5, vec![], None);
        let car_pos_10 = Car::new(validator_id, 10, vec![], None);

        let mut last_cut = Cut::new(1);
        last_cut.cars.insert(validator_id, car_pos_5);

        let mut new_cut = Cut::new(2);
        new_cut.cars.insert(validator_id, car_pos_10.clone());

        assert!(new_cut.is_monotonic(&last_cut));

        // Position going backwards should fail
        let car_pos_3 = Car::new(validator_id, 3, vec![], None);
        let mut bad_cut = Cut::new(2);
        bad_cut.cars.insert(validator_id, car_pos_3);

        assert!(!bad_cut.is_monotonic(&last_cut));
    }

    #[test]
    fn test_anti_censorship() {
        let validators: Vec<ValidatorId> = (0..10)
            .map(|i| ValidatorId::from_bytes([i as u8; 32]))
            .collect();

        let mut cut = Cut::new(1);
        // Include only first 7 validators
        for v in validators.iter().take(7) {
            cut.cars.insert(*v, Car::new(*v, 0, vec![], None));
        }

        // 3 excluded, with max_excluded = 3, should pass
        assert!(cut.check_anti_censorship(&validators, 3));

        // With max_excluded = 2, should fail
        assert!(!cut.check_anti_censorship(&validators, 2));
    }

    #[test]
    fn test_total_tx_count() {
        let validator_id = ValidatorId::from_bytes([1u8; 32]);

        let digests = vec![
            BatchDigest::new(0, Hash::compute(b"1"), 100, 1000),
            BatchDigest::new(1, Hash::compute(b"2"), 50, 500),
        ];

        let car = Car::new(validator_id, 0, digests, None);

        let mut cut = Cut::new(1);
        cut.cars.insert(validator_id, car);

        assert_eq!(cut.total_tx_count(), 150);
        assert_eq!(cut.total_bytes(), 1500);
    }

    #[test]
    fn test_excluded_validators() {
        let validators: Vec<ValidatorId> = (0..5)
            .map(|i| ValidatorId::from_bytes([i as u8; 32]))
            .collect();

        let mut cut = Cut::new(1);
        cut.cars
            .insert(validators[0], Car::new(validators[0], 0, vec![], None));
        cut.cars
            .insert(validators[2], Car::new(validators[2], 0, vec![], None));

        let excluded = cut.excluded_validators(&validators);
        assert_eq!(excluded.len(), 3);
        assert!(excluded.contains(&validators[1]));
        assert!(excluded.contains(&validators[3]));
        assert!(excluded.contains(&validators[4]));
    }
}
