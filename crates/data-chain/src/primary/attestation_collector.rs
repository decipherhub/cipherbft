//! Attestation collector for Primary
//!
//! Collects individual attestations and aggregates them when f+1 threshold is reached.

use crate::attestation::{AggregatedAttestation, Attestation};
use crate::car::Car;
use crate::error::DclError;
use cipherbft_types::{Hash, ValidatorId};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Pending attestation collection for a Car
#[derive(Debug)]
struct PendingAttestation {
    /// The Car being attested
    car: Car,
    /// Attestations received (attester -> attestation)
    attestations: HashMap<ValidatorId, Attestation>,
    /// When collection started
    started_at: Instant,
    /// Current backoff duration
    current_backoff: Duration,
}

impl PendingAttestation {
    fn new(car: Car, base_timeout: Duration) -> Self {
        Self {
            car,
            attestations: HashMap::new(),
            started_at: Instant::now(),
            current_backoff: base_timeout,
        }
    }
}

/// Attestation collector
pub struct AttestationCollector {
    /// Our validator ID (implicit self-attestation)
    our_id: ValidatorId,
    /// Pending attestations by Car hash
    pending: HashMap<Hash, PendingAttestation>,
    /// Attestation threshold (f+1)
    threshold: usize,
    /// Validator count (for BitVec sizing)
    validator_count: usize,
    /// Validator index mapping
    validator_indices: HashMap<ValidatorId, usize>,
    /// Base timeout for attestation collection
    base_timeout: Duration,
    /// Maximum timeout for attestation collection
    max_timeout: Duration,
}

impl AttestationCollector {
    /// Create a new attestation collector
    pub fn new(
        our_id: ValidatorId,
        threshold: usize,
        validator_count: usize,
        validator_indices: HashMap<ValidatorId, usize>,
        base_timeout: Duration,
        max_timeout: Duration,
    ) -> Self {
        Self {
            our_id,
            pending: HashMap::new(),
            threshold,
            validator_count,
            validator_indices,
            base_timeout,
            max_timeout,
        }
    }

    /// Start collecting attestations for a Car (our own Car)
    pub fn start_collection(&mut self, car: Car) {
        let hash = car.hash();
        self.pending
            .insert(hash, PendingAttestation::new(car, self.base_timeout));
    }

    /// Add an attestation
    ///
    /// # Returns
    /// * `Ok(Some(AggregatedAttestation))` - Threshold reached, aggregation complete
    /// * `Ok(None)` - Attestation added, but threshold not yet reached
    /// * `Err(_)` - Invalid attestation or unknown Car
    pub fn add_attestation(
        &mut self,
        attestation: Attestation,
    ) -> Result<Option<AggregatedAttestation>, DclError> {
        let car_hash = attestation.car_hash;

        let Some(pending) = self.pending.get_mut(&car_hash) else {
            return Err(DclError::UnknownCar { car_hash });
        };

        // Check for duplicate
        if pending.attestations.contains_key(&attestation.attester) {
            return Err(DclError::DuplicateAttestation {
                attester: attestation.attester,
                car_hash,
            });
        }

        // Get validator index (verify attester is known)
        let Some(&_attester_idx) = self.validator_indices.get(&attestation.attester) else {
            return Err(DclError::UnknownValidator {
                validator: attestation.attester,
            });
        };

        // Add attestation
        pending
            .attestations
            .insert(attestation.attester, attestation);

        // Check if threshold reached (including self-attestation)
        // Self-attestation is implicit for our own Cars
        let attestation_count = pending.attestations.len() + 1; // +1 for self

        if attestation_count >= self.threshold {
            // Aggregate and return
            let agg = self.aggregate(&car_hash)?;
            self.pending.remove(&car_hash);
            return Ok(Some(agg));
        }

        Ok(None)
    }

    /// Aggregate attestations for a Car
    fn aggregate(&self, car_hash: &Hash) -> Result<AggregatedAttestation, DclError> {
        let Some(pending) = self.pending.get(car_hash) else {
            return Err(DclError::UnknownCar {
                car_hash: *car_hash,
            });
        };

        // Build attestations with indices
        let attestations: Vec<(Attestation, usize)> = pending
            .attestations
            .iter()
            .filter_map(|(validator, att)| {
                self.validator_indices
                    .get(validator)
                    .map(|&idx| (att.clone(), idx))
            })
            .collect();

        AggregatedAttestation::aggregate_with_indices(&attestations, self.validator_count)
            .ok_or_else(|| DclError::ThresholdNotMet {
                got: attestations.len(),
                threshold: self.threshold,
            })
    }

    /// Check for timed-out attestations
    ///
    /// Returns Cars that have timed out and should be excluded from Cut
    pub fn check_timeouts(&mut self) -> Vec<(Hash, Car)> {
        let now = Instant::now();
        let mut timed_out = Vec::new();

        for (hash, pending) in &self.pending {
            let elapsed = now.duration_since(pending.started_at);
            if elapsed >= pending.current_backoff {
                timed_out.push((*hash, pending.car.clone()));
            }
        }

        timed_out
    }

    /// Apply exponential backoff to a timed-out Car
    ///
    /// Returns true if Car should be retried, false if max timeout exceeded
    pub fn apply_backoff(&mut self, car_hash: &Hash) -> bool {
        if let Some(pending) = self.pending.get_mut(car_hash) {
            // Double the backoff
            let new_backoff = pending.current_backoff * 2;
            if new_backoff > self.max_timeout {
                // Max timeout exceeded, remove from pending
                return false;
            }
            pending.current_backoff = new_backoff;
            pending.started_at = Instant::now();
            true
        } else {
            false
        }
    }

    /// Remove a Car from collection (e.g., after max timeout)
    pub fn remove(&mut self, car_hash: &Hash) -> Option<Car> {
        self.pending.remove(car_hash).map(|p| p.car)
    }

    /// Get current attestation count for a Car
    pub fn attestation_count(&self, car_hash: &Hash) -> Option<usize> {
        self.pending.get(car_hash).map(|p| p.attestations.len() + 1) // +1 for self
    }

    /// Check if a Car is pending
    pub fn is_pending(&self, car_hash: &Hash) -> bool {
        self.pending.contains_key(car_hash)
    }

    /// Get pending Car hashes
    pub fn pending_car_hashes(&self) -> Vec<Hash> {
        self.pending.keys().cloned().collect()
    }

    /// Get attesters for a pending Car
    pub fn attesters(&self, car_hash: &Hash) -> Vec<ValidatorId> {
        self.pending
            .get(car_hash)
            .map(|p| p.attestations.keys().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;

    fn make_test_setup(n: usize) -> (AttestationCollector, Vec<BlsKeyPair>) {
        let keypairs: Vec<BlsKeyPair> = (0..n)
            .map(|_| BlsKeyPair::generate(&mut rand::thread_rng()))
            .collect();

        let validator_indices: HashMap<_, _> = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| (ValidatorId::from_bytes(kp.public_key.hash()), i))
            .collect();

        let our_id = ValidatorId::from_bytes(keypairs[0].public_key.hash());
        let threshold = (n - 1) / 3 + 1; // f+1

        let collector = AttestationCollector::new(
            our_id,
            threshold,
            n,
            validator_indices,
            Duration::from_millis(500),
            Duration::from_millis(5000),
        );

        (collector, keypairs)
    }

    fn make_car(keypair: &BlsKeyPair) -> Car {
        let validator_id = ValidatorId::from_bytes(keypair.public_key.hash());
        let mut car = Car::new(validator_id, 0, vec![], None);
        car.signature = keypair.sign_car(&car.signing_bytes());
        car
    }

    fn make_attestation(car: &Car, attester_keypair: &BlsKeyPair) -> Attestation {
        let attester_id = ValidatorId::from_bytes(attester_keypair.public_key.hash());
        let mut att = Attestation::from_car(car, attester_id);
        att.signature = attester_keypair.sign_attestation(&att.get_signing_bytes());
        att
    }

    #[test]
    fn test_collection_start() {
        let (mut collector, keypairs) = make_test_setup(4);
        let car = make_car(&keypairs[0]);
        let car_hash = car.hash();

        collector.start_collection(car);
        assert!(collector.is_pending(&car_hash));
        assert_eq!(collector.attestation_count(&car_hash), Some(1)); // self-attestation
    }

    #[test]
    fn test_threshold_reached() {
        // n=4, f=1, threshold=2
        let (mut collector, keypairs) = make_test_setup(4);
        let car = make_car(&keypairs[0]);
        let car_hash = car.hash();

        collector.start_collection(car.clone());

        // Add one attestation (self + 1 = 2 = threshold)
        let att = make_attestation(&car, &keypairs[1]);
        let result = collector.add_attestation(att).unwrap();

        assert!(result.is_some());
        let agg = result.unwrap();
        assert_eq!(agg.car_hash, car_hash);
    }

    #[test]
    fn test_duplicate_attestation() {
        let (mut collector, keypairs) = make_test_setup(7);
        let car = make_car(&keypairs[0]);

        collector.start_collection(car.clone());

        // Add first attestation
        let att1 = make_attestation(&car, &keypairs[1]);
        collector.add_attestation(att1.clone()).unwrap();

        // Try to add duplicate
        let result = collector.add_attestation(att1);
        assert!(matches!(result, Err(DclError::DuplicateAttestation { .. })));
    }

    #[test]
    fn test_unknown_car() {
        let (mut collector, keypairs) = make_test_setup(4);
        let car = make_car(&keypairs[0]);

        // Don't start collection, try to add attestation
        let att = make_attestation(&car, &keypairs[1]);
        let result = collector.add_attestation(att);
        assert!(matches!(result, Err(DclError::UnknownCar { .. })));
    }

    #[test]
    fn test_remove_pending() {
        let (mut collector, keypairs) = make_test_setup(4);
        let car = make_car(&keypairs[0]);
        let car_hash = car.hash();

        collector.start_collection(car);
        assert!(collector.is_pending(&car_hash));

        let removed = collector.remove(&car_hash);
        assert!(removed.is_some());
        assert!(!collector.is_pending(&car_hash));
    }
}
