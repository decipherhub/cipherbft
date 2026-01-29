//! Core message processor for Primary
//!
//! Handles Car verification and attestation generation.

use crate::attestation::Attestation;
use crate::car::Car;
use crate::error::DclError;
use crate::primary::state::PrimaryState;
use cipherbft_crypto::{BlsKeyPair, BlsPublicKey};
use cipherbft_types::ValidatorId;
use std::collections::HashMap;

/// Core message processor for Primary
pub struct Core {
    /// Our validator identity
    our_id: ValidatorId,
    /// Our BLS key pair for signing attestations
    keypair: BlsKeyPair,
    /// Public keys of all validators (index -> pubkey)
    validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
    /// Validator index mapping (ValidatorId -> index)
    validator_indices: HashMap<ValidatorId, usize>,
    /// Ordered list of validators (for round-robin)
    validators: Vec<ValidatorId>,
}

impl Core {
    /// Create a new Core processor
    pub fn new(
        our_id: ValidatorId,
        keypair: BlsKeyPair,
        validator_pubkeys: HashMap<ValidatorId, BlsPublicKey>,
    ) -> Self {
        let mut validators: Vec<ValidatorId> = validator_pubkeys.keys().cloned().collect();
        validators.sort(); // Deterministic ordering

        // Log what validators Core is initialized with
        tracing::info!(
            our_id = %our_id,
            validator_count = validators.len(),
            validators = ?validators,
            "Core initialized with validators"
        );

        let validator_indices: HashMap<_, _> = validators
            .iter()
            .enumerate()
            .map(|(i, v)| (*v, i))
            .collect();

        Self {
            our_id,
            keypair,
            validator_pubkeys,
            validator_indices,
            validators,
        }
    }

    /// Process a received Car
    ///
    /// # Returns
    /// * `Ok(Some(Attestation))` - Car is valid, attestation generated
    /// * `Ok(None)` - Car is valid but we can't attest yet (missing batches)
    /// * `Err(_)` - Car is invalid
    pub fn handle_car(
        &self,
        car: &Car,
        state: &mut PrimaryState,
        has_all_batches: bool,
    ) -> Result<Option<Attestation>, DclError> {
        // 1. Verify Car signature
        let Some(proposer_pubkey) = self.validator_pubkeys.get(&car.proposer) else {
            // Log what validators we DO know about for debugging
            let known_validators: Vec<_> = self.validator_pubkeys.keys().collect();
            tracing::warn!(
                car_proposer = %car.proposer,
                known_count = known_validators.len(),
                known_validators = ?known_validators,
                "Rejecting Car from unknown validator"
            );
            return Err(DclError::UnknownValidator {
                validator: car.proposer,
            });
        };

        if !car.verify(proposer_pubkey) {
            return Err(DclError::InvalidCarSignature {
                validator: car.proposer,
            });
        }

        // 2. Verify batch digests are sorted
        if !car.is_sorted() {
            return Err(DclError::UnsortedBatchDigests {
                validator: car.proposer,
            });
        }

        // 3. Verify position is sequential
        let expected_position = state.expected_position(&car.proposer);
        if car.position != expected_position {
            return Err(DclError::PositionGap {
                validator: car.proposer,
                expected: expected_position,
                actual: car.position,
            });
        }

        // 4. Verify parent_ref
        if car.position == 0 {
            if car.parent_ref.is_some() {
                return Err(DclError::ParentHashMismatch {
                    validator: car.proposer,
                    position: car.position,
                });
            }
        } else {
            let expected_parent = state.last_seen_car_hash(&car.proposer);
            match (&car.parent_ref, expected_parent) {
                (Some(parent), Some(expected)) if parent == expected => {
                    // Valid parent ref
                }
                (None, _) => {
                    return Err(DclError::ParentHashMismatch {
                        validator: car.proposer,
                        position: car.position,
                    });
                }
                (Some(_), None) => {
                    return Err(DclError::MissingParentCar {
                        validator: car.proposer,
                        position: car.position,
                    });
                }
                (Some(_), Some(_)) => {
                    return Err(DclError::ParentHashMismatch {
                        validator: car.proposer,
                        position: car.position,
                    });
                }
            }
        }

        // 5. Check for equivocation
        let car_hash = car.hash();
        if let Some(existing_hash) = state.last_seen_car_hash(&car.proposer) {
            if state.last_seen_positions.get(&car.proposer) == Some(&car.position) {
                // Same position but we already have a car
                if *existing_hash != car_hash {
                    // Equivocation detected!
                    state.record_equivocation(car.proposer, car.position, car_hash);
                    return Err(DclError::Equivocation {
                        validator: car.proposer,
                        position: car.position,
                    });
                }
            }
        }

        // 6. Update state with this Car
        state.update_last_seen(car.proposer, car.position, car_hash);

        // 7. If we have all batches, create attestation
        if !has_all_batches {
            return Ok(None);
        }

        // Create attestation
        let attestation = self.create_attestation(car);
        Ok(Some(attestation))
    }

    /// Create an attestation for a valid Car
    pub fn create_attestation(&self, car: &Car) -> Attestation {
        let mut attestation = Attestation::from_car(car, self.our_id);
        let signing_bytes = attestation.get_signing_bytes();
        attestation.signature = self.keypair.sign_attestation(&signing_bytes);
        attestation
    }

    /// Verify an attestation
    pub fn verify_attestation(&self, attestation: &Attestation) -> Result<(), DclError> {
        let Some(attester_pubkey) = self.validator_pubkeys.get(&attestation.attester) else {
            return Err(DclError::UnknownValidator {
                validator: attestation.attester,
            });
        };

        if !attestation.verify(attester_pubkey) {
            return Err(DclError::InvalidAttestationSignature {
                attester: attestation.attester,
            });
        }

        Ok(())
    }

    /// Get validator index
    pub fn validator_index(&self, validator: &ValidatorId) -> Option<usize> {
        self.validator_indices.get(validator).copied()
    }

    /// Get validator by index
    pub fn validator_at(&self, index: usize) -> Option<ValidatorId> {
        self.validators.get(index).copied()
    }

    /// Get validator count
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Calculate f (Byzantine tolerance)
    pub fn f(&self) -> usize {
        (self.validator_count() - 1) / 3
    }

    /// Calculate attestation threshold (f + 1)
    pub fn attestation_threshold(&self) -> usize {
        self.f() + 1
    }

    /// Get next validator in round-robin order
    pub fn next_validator_round_robin(&self, current_idx: usize) -> (usize, ValidatorId) {
        let next_idx = (current_idx + 1) % self.validators.len();
        (next_idx, self.validators[next_idx])
    }

    /// Get our validator ID
    pub fn our_id(&self) -> ValidatorId {
        self.our_id
    }

    /// Get public key for a validator
    pub fn get_pubkey(&self, validator: &ValidatorId) -> Option<&BlsPublicKey> {
        self.validator_pubkeys.get(validator)
    }

    /// Get public key by index
    pub fn get_pubkey_by_index(&self, index: usize) -> Option<BlsPublicKey> {
        self.validators
            .get(index)
            .and_then(|v| self.validator_pubkeys.get(v))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_types::{Hash, VALIDATOR_ID_SIZE};

    /// Helper to derive ValidatorId from BLS public key (for tests only)
    fn validator_id_from_bls_pubkey(pubkey: &cipherbft_crypto::BlsPublicKey) -> ValidatorId {
        let hash = pubkey.hash();
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes.copy_from_slice(&hash[12..32]); // last 20 bytes
        ValidatorId::from_bytes(bytes)
    }

    fn make_test_setup(n: usize) -> (Core, Vec<BlsKeyPair>, PrimaryState) {
        let keypairs: Vec<BlsKeyPair> = (0..n)
            .map(|_| BlsKeyPair::generate(&mut rand::thread_rng()))
            .collect();

        let validator_pubkeys: HashMap<_, _> = keypairs
            .iter()
            .map(|kp| {
                let id = validator_id_from_bls_pubkey(&kp.public_key);
                (id, kp.public_key.clone())
            })
            .collect();

        let our_id = validator_id_from_bls_pubkey(&keypairs[0].public_key);
        let core = Core::new(our_id, keypairs[0].clone(), validator_pubkeys);
        let state = PrimaryState::new(our_id, 1000);

        (core, keypairs, state)
    }

    fn make_car(keypair: &BlsKeyPair, position: u64, parent_ref: Option<Hash>) -> Car {
        let validator_id = validator_id_from_bls_pubkey(&keypair.public_key);
        let mut car = Car::new(validator_id, position, vec![], parent_ref);
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);
        car
    }

    #[test]
    fn test_handle_valid_car() {
        let (core, keypairs, mut state) = make_test_setup(4);

        // Car from validator 1
        let car = make_car(&keypairs[1], 0, None);

        let result = core.handle_car(&car, &mut state, true);
        assert!(result.is_ok());
        let attestation = result.unwrap().unwrap();

        // Verify attestation
        assert!(core.verify_attestation(&attestation).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let (core, keypairs, mut state) = make_test_setup(4);

        // Create car with wrong signature
        let validator_id = validator_id_from_bls_pubkey(&keypairs[1].public_key);
        let mut car = Car::new(validator_id, 0, vec![], None);
        // Sign with wrong key
        car.signature = keypairs[2].sign_car(&car.signing_bytes());

        let result = core.handle_car(&car, &mut state, true);
        assert!(matches!(result, Err(DclError::InvalidCarSignature { .. })));
    }

    #[test]
    fn test_position_gap() {
        let (core, keypairs, mut state) = make_test_setup(4);

        // Skip position 0, try to submit position 1
        let car = make_car(&keypairs[1], 1, Some(Hash::compute(b"fake")));

        let result = core.handle_car(&car, &mut state, true);
        assert!(matches!(result, Err(DclError::PositionGap { .. })));
    }

    #[test]
    fn test_sequential_cars() {
        let (core, keypairs, mut state) = make_test_setup(4);

        // First car at position 0
        let car0 = make_car(&keypairs[1], 0, None);
        let result0 = core.handle_car(&car0, &mut state, true);
        assert!(result0.is_ok());

        // Second car at position 1 with correct parent
        let car1 = make_car(&keypairs[1], 1, Some(car0.hash()));
        let result1 = core.handle_car(&car1, &mut state, true);
        assert!(result1.is_ok());
    }

    #[test]
    fn test_parent_hash_mismatch() {
        let (core, keypairs, mut state) = make_test_setup(4);

        // First car
        let car0 = make_car(&keypairs[1], 0, None);
        core.handle_car(&car0, &mut state, true).unwrap();

        // Second car with wrong parent hash
        let car1 = make_car(&keypairs[1], 1, Some(Hash::compute(b"wrong")));
        let result = core.handle_car(&car1, &mut state, true);
        assert!(matches!(result, Err(DclError::ParentHashMismatch { .. })));
    }

    #[test]
    fn test_threshold_calculation() {
        // n=4, f=1, threshold=2
        let (core, _, _) = make_test_setup(4);
        assert_eq!(core.f(), 1);
        assert_eq!(core.attestation_threshold(), 2);

        // n=7, f=2, threshold=3
        let (core, _, _) = make_test_setup(7);
        assert_eq!(core.f(), 2);
        assert_eq!(core.attestation_threshold(), 3);

        // n=21, f=6, threshold=7
        let (core, _, _) = make_test_setup(21);
        assert_eq!(core.f(), 6);
        assert_eq!(core.attestation_threshold(), 7);
    }

    #[test]
    fn test_round_robin() {
        let (core, _, _) = make_test_setup(4);

        let (idx1, _) = core.next_validator_round_robin(0);
        assert_eq!(idx1, 1);

        let (idx2, _) = core.next_validator_round_robin(3);
        assert_eq!(idx2, 0); // Wraps around
    }

    #[test]
    fn test_missing_batches_no_attestation() {
        let (core, keypairs, mut state) = make_test_setup(4);

        let car = make_car(&keypairs[1], 0, None);

        // has_all_batches = false
        let result = core.handle_car(&car, &mut state, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No attestation generated
    }
}
