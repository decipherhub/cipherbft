//! Attestation collector for Primary
//!
//! Collects individual attestations and aggregates them when f+1 threshold is reached.

use crate::attestation::{AggregatedAttestation, Attestation};
use crate::car::Car;
use crate::error::DclError;
use cipherbft_metrics::dcl::DCL_ATTESTATION_COLLECTION;
use cipherbft_types::{Hash, ValidatorId};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum number of timeout resets allowed for batched Cars.
/// This prevents Cars from being stuck indefinitely when peers cannot sync batches.
const MAX_BATCHED_CAR_RESETS: u32 = 10;

/// Pending attestation collection for a Car
#[derive(Debug)]
struct PendingAttestation {
    /// The Car being attested
    car: Car,
    /// Proposer's own attestation (self-attestation)
    /// This MUST be included in the aggregated signature for correct verification
    self_attestation: Attestation,
    /// Attestations received from other validators (attester -> attestation)
    attestations: HashMap<ValidatorId, Attestation>,
    /// When collection started
    started_at: Instant,
    /// Current backoff duration
    current_backoff: Duration,
    /// Number of times the timeout has been reset (for batched Cars)
    reset_count: u32,
}

impl PendingAttestation {
    fn new(car: Car, self_attestation: Attestation, base_timeout: Duration) -> Self {
        Self {
            car,
            self_attestation,
            attestations: HashMap::new(),
            started_at: Instant::now(),
            current_backoff: base_timeout,
            reset_count: 0,
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
    ///
    /// The proposer MUST provide their own attestation (self-attestation) which
    /// will be included in the aggregated signature. This is required for correct
    /// verification per FR-002: "Self-attestation counts as 1 (implicit)".
    ///
    /// # Arguments
    /// * `car` - The Car created by this validator
    /// * `self_attestation` - Proposer's own signed attestation for this Car
    pub fn start_collection(&mut self, car: Car, self_attestation: Attestation) {
        let hash = car.hash();
        self.pending.insert(
            hash,
            PendingAttestation::new(car, self_attestation, self.base_timeout),
        );
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
            // Track attestation collection latency
            let elapsed = pending.started_at.elapsed();
            DCL_ATTESTATION_COLLECTION
                .with_label_values(&[])
                .observe(elapsed.as_secs_f64());

            // Aggregate and return
            let agg = self.aggregate(&car_hash)?;
            self.pending.remove(&car_hash);
            return Ok(Some(agg));
        }

        Ok(None)
    }

    /// Aggregate attestations for a Car
    ///
    /// Uses `aggregate_with_self()` to ensure the proposer's self-attestation
    /// is included in the aggregated signature.
    fn aggregate(&self, car_hash: &Hash) -> Result<AggregatedAttestation, DclError> {
        let Some(pending) = self.pending.get(car_hash) else {
            return Err(DclError::UnknownCar {
                car_hash: *car_hash,
            });
        };

        // Get proposer's validator index for self-attestation
        let self_index =
            self.validator_indices
                .get(&self.our_id)
                .ok_or(DclError::UnknownValidator {
                    validator: self.our_id,
                })?;

        // Build external attestations with indices
        let attestations: Vec<(Attestation, usize)> = pending
            .attestations
            .iter()
            .filter_map(|(validator, att)| {
                self.validator_indices
                    .get(validator)
                    .map(|&idx| (att.clone(), idx))
            })
            .collect();

        // Aggregate with self-attestation included
        AggregatedAttestation::aggregate_with_self(
            &attestations,
            &pending.self_attestation,
            *self_index,
            self.validator_count,
        )
        .ok_or_else(|| DclError::ThresholdNotMet {
            got: attestations.len() + 1, // +1 for self-attestation
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

    /// Reset timeout for a Car without losing existing attestations
    ///
    /// Used for batched Cars that need extra time for peers to sync batch data.
    /// Returns true if the Car was found and reset successfully.
    /// Returns false if the Car was not found OR if max reset count exceeded.
    ///
    /// This prevents Cars from being stuck indefinitely when peers cannot sync batches
    /// (e.g., due to position divergence where peers reject the Car).
    pub fn reset_timeout(&mut self, car_hash: &Hash) -> bool {
        if let Some(pending) = self.pending.get_mut(car_hash) {
            // Check if we've exceeded max resets
            if pending.reset_count >= MAX_BATCHED_CAR_RESETS {
                return false;
            }
            pending.started_at = std::time::Instant::now();
            pending.current_backoff = self.base_timeout;
            pending.reset_count += 1;
            true
        } else {
            false
        }
    }

    /// Get the reset count for a pending Car
    pub fn reset_count(&self, car_hash: &Hash) -> Option<u32> {
        self.pending.get(car_hash).map(|p| p.reset_count)
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

    /// Update validator set (epoch change)
    ///
    /// This is called when the consensus layer notifies us of a new validator set.
    /// We update our threshold and validator indices to reflect the new set.
    ///
    /// # Arguments
    /// * `threshold` - New attestation threshold (2f + 1)
    /// * `validator_count` - New total validator count
    /// * `validator_indices` - New mapping of ValidatorId to index
    pub fn update_validators(
        &mut self,
        threshold: usize,
        validator_count: usize,
        validator_indices: HashMap<ValidatorId, usize>,
    ) {
        tracing::info!(
            old_threshold = self.threshold,
            new_threshold = threshold,
            old_count = self.validator_count,
            new_count = validator_count,
            "Updating attestation collector validator set"
        );

        self.threshold = threshold;
        self.validator_count = validator_count;
        self.validator_indices = validator_indices;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_types::genesis::AttestationQuorum;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    /// Helper to derive ValidatorId from BLS public key (for tests only)
    fn validator_id_from_bls_pubkey(pubkey: &cipherbft_crypto::BlsPublicKey) -> ValidatorId {
        let hash = pubkey.hash();
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes.copy_from_slice(&hash[12..32]); // last 20 bytes
        ValidatorId::from_bytes(bytes)
    }

    fn make_test_setup(n: usize) -> (AttestationCollector, Vec<BlsKeyPair>) {
        let keypairs: Vec<BlsKeyPair> = (0..n)
            .map(|_| BlsKeyPair::generate(&mut rand::thread_rng()))
            .collect();

        let validator_indices: HashMap<_, _> = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| (validator_id_from_bls_pubkey(&kp.public_key), i))
            .collect();

        let our_id = validator_id_from_bls_pubkey(&keypairs[0].public_key);
        let threshold = AttestationQuorum::TwoFPlusOne.compute_threshold(n);

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
        let validator_id = validator_id_from_bls_pubkey(&keypair.public_key);
        let mut car = Car::new(validator_id, 0, vec![], None);
        car.signature = keypair.sign_car(&car.signing_bytes());
        car
    }

    fn make_attestation(car: &Car, attester_keypair: &BlsKeyPair) -> Attestation {
        let attester_id = validator_id_from_bls_pubkey(&attester_keypair.public_key);
        let mut att = Attestation::from_car(car, attester_id);
        att.signature = attester_keypair.sign_attestation(&att.get_signing_bytes());
        att
    }

    #[test]
    fn test_collection_start() {
        let (mut collector, keypairs) = make_test_setup(4);
        let car = make_car(&keypairs[0]);
        let car_hash = car.hash();
        let self_attestation = make_attestation(&car, &keypairs[0]);

        collector.start_collection(car, self_attestation);
        assert!(collector.is_pending(&car_hash));
        assert_eq!(collector.attestation_count(&car_hash), Some(1)); // self-attestation
    }

    #[test]
    fn test_threshold_reached() {
        // n=4, f=1, threshold=2f+1=3
        let (mut collector, keypairs) = make_test_setup(4);
        let car = make_car(&keypairs[0]);
        let car_hash = car.hash();
        let self_attestation = make_attestation(&car, &keypairs[0]);

        collector.start_collection(car.clone(), self_attestation);

        // Add first attestation (self + 1 = 2, below threshold)
        let att1 = make_attestation(&car, &keypairs[1]);
        let result1 = collector.add_attestation(att1).unwrap();
        assert!(result1.is_none());

        // Add second attestation (self + 2 = 3 = threshold)
        let att2 = make_attestation(&car, &keypairs[2]);
        let result2 = collector.add_attestation(att2).unwrap();

        assert!(result2.is_some());
        let agg = result2.unwrap();
        assert_eq!(agg.car_hash, car_hash);
    }

    #[test]
    fn test_threshold_reached_with_verification() {
        // n=4, f=1, threshold=2f+1=3
        // This test verifies the aggregated signature is correct
        let (mut collector, keypairs) = make_test_setup(4);
        let car = make_car(&keypairs[0]);
        let self_attestation = make_attestation(&car, &keypairs[0]);

        collector.start_collection(car.clone(), self_attestation);

        // Add first attestation (self + 1 = 2, below threshold)
        let att1 = make_attestation(&car, &keypairs[1]);
        let result1 = collector.add_attestation(att1).unwrap();
        assert!(result1.is_none());

        // Add second attestation (self + 2 = 3 = threshold)
        let att2 = make_attestation(&car, &keypairs[2]);
        let result2 = collector.add_attestation(att2).unwrap();

        assert!(result2.is_some());
        let agg = result2.unwrap();

        // Build public key lookup
        let pubkeys: Vec<_> = keypairs.iter().map(|kp| kp.public_key.clone()).collect();

        // Verify the aggregated signature
        assert!(agg.verify(|idx| pubkeys.get(idx).cloned()));

        // Verify count includes self and two external attestations
        assert_eq!(agg.count(), 3);

        // Verify bitmap has all three validators set
        assert!(agg.has_attested(0)); // proposer (self)
        assert!(agg.has_attested(1)); // first external attester
        assert!(agg.has_attested(2)); // second external attester
    }

    #[test]
    fn test_duplicate_attestation() {
        let (mut collector, keypairs) = make_test_setup(7);
        let car = make_car(&keypairs[0]);
        let self_attestation = make_attestation(&car, &keypairs[0]);

        collector.start_collection(car.clone(), self_attestation);

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
        let self_attestation = make_attestation(&car, &keypairs[0]);

        collector.start_collection(car, self_attestation);
        assert!(collector.is_pending(&car_hash));

        let removed = collector.remove(&car_hash);
        assert!(removed.is_some());
        assert!(!collector.is_pending(&car_hash));
    }
}
