//! Attestation types for DCL data availability
//!
//! Attestations confirm that a validator has all batch data for a Car.
//! f+1 attestations are required for a Car to be included in a Cut.

use crate::car::Car;
use bitvec::prelude::*;
use cipherbft_crypto::{BlsAggregateSignature, BlsPublicKey, BlsSignature, DST_ATTESTATION};
use cipherbft_types::{Hash, ValidatorId};
use serde::{Deserialize, Serialize};

/// An attestation confirms data availability for a Car
///
/// Created by a validator after verifying:
/// 1. Car signature is valid
/// 2. Car position is correct (last_seen + 1)
/// 3. All referenced batches are available locally
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Hash of the attested Car
    pub car_hash: Hash,
    /// Position of the attested Car
    pub car_position: u64,
    /// Validator who created the Car
    pub car_proposer: ValidatorId,
    /// Validator who is attesting
    pub attester: ValidatorId,
    /// BLS signature over (car_hash, car_position, car_proposer)
    pub signature: BlsSignature,
}

impl Attestation {
    /// Create a new attestation (unsigned - must set signature after)
    pub fn new(
        car_hash: Hash,
        car_position: u64,
        car_proposer: ValidatorId,
        attester: ValidatorId,
    ) -> Self {
        Self {
            car_hash,
            car_position,
            car_proposer,
            attester,
            signature: BlsSignature::default(),
        }
    }

    /// Create attestation from a Car
    pub fn from_car(car: &Car, attester: ValidatorId) -> Self {
        Self::new(car.hash(), car.position, car.proposer, attester)
    }

    /// Message bytes for signing
    ///
    /// Format: car_hash (32) || car_position (8) || car_proposer (20) = 60 bytes
    pub fn signing_bytes(
        car_hash: &Hash,
        car_position: u64,
        car_proposer: &ValidatorId,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(60);
        buf.extend_from_slice(car_hash.as_bytes()); // 32 bytes
        buf.extend_from_slice(&car_position.to_le_bytes()); // 8 bytes
        buf.extend_from_slice(car_proposer.as_bytes()); // 20 bytes
        buf
    }

    /// Get signing bytes for this attestation
    pub fn get_signing_bytes(&self) -> Vec<u8> {
        Self::signing_bytes(&self.car_hash, self.car_position, &self.car_proposer)
    }

    /// Verify attestation signature
    pub fn verify(&self, attester_pubkey: &BlsPublicKey) -> bool {
        let msg = self.get_signing_bytes();
        self.signature
            .verify(&msg, DST_ATTESTATION, attester_pubkey)
    }
}

/// Aggregated BLS attestation for a Car (f+1 validators)
///
/// Contains a single aggregated signature from multiple validators,
/// identified by a bitmap of which validators attested.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedAttestation {
    /// Hash of the attested Car
    pub car_hash: Hash,
    /// Position of the attested Car
    pub car_position: u64,
    /// Proposer of the attested Car
    pub car_proposer: ValidatorId,
    /// Bitmap indicating which validators attested (by validator index)
    #[serde(with = "bitvec_serde")]
    pub validators: BitVec<u8, Lsb0>,
    /// Single aggregated BLS signature
    pub aggregated_signature: BlsAggregateSignature,
}

impl AggregatedAttestation {
    /// Create from individual attestations without validator indices.
    ///
    /// # Deprecated
    ///
    /// This method is **deprecated** and will always return `None`. The method cannot
    /// correctly populate the validator bitmap without knowing each attestation's
    /// validator index, which means the resulting `AggregatedAttestation` would fail
    /// verification since `verify()` relies on the bitmap to select public keys.
    ///
    /// Use [`aggregate_with_indices`](Self::aggregate_with_indices) instead, which
    /// takes `(Attestation, usize)` pairs where the `usize` is the validator's index
    /// in the validator set.
    ///
    /// For proposers creating self-attestations, use
    /// [`aggregate_with_self`](Self::aggregate_with_self) which handles the proposer's
    /// own attestation separately.
    ///
    /// # Returns
    ///
    /// Always returns `None`. Use `aggregate_with_indices()` for proper aggregation.
    #[deprecated(
        since = "0.1.0",
        note = "Cannot populate bitmap without validator indices. Use aggregate_with_indices() instead."
    )]
    pub fn aggregate(_attestations: &[Attestation], _validator_count: usize) -> Option<Self> {
        // This method cannot work correctly without validator index mapping.
        // The bitmap must be populated with the correct validator indices for
        // verify() to work, but we don't have that information here.
        //
        // Previously this returned an AggregatedAttestation with an all-zero bitmap,
        // which would always fail verification. Now we return None to make the
        // failure explicit at aggregation time rather than verification time.
        None
    }

    /// Create from attestations with validator index mapping
    pub fn aggregate_with_indices(
        attestations: &[(Attestation, usize)], // (attestation, validator_index)
        validator_count: usize,
    ) -> Option<Self> {
        if attestations.is_empty() {
            return None;
        }

        let first = &attestations[0].0;
        let car_hash = first.car_hash;
        let car_position = first.car_position;
        let car_proposer = first.car_proposer;

        // Build validator bitmap and collect signatures
        let mut validators = bitvec![u8, Lsb0; 0; validator_count];
        let mut sigs: Vec<&BlsSignature> = Vec::with_capacity(attestations.len());

        for (att, idx) in attestations {
            if att.car_hash != car_hash {
                return None;
            }
            if *idx < validator_count {
                validators.set(*idx, true);
            }
            sigs.push(&att.signature);
        }

        // Aggregate signatures
        let aggregated_signature = BlsAggregateSignature::aggregate(&sigs).ok()?;

        Some(Self {
            car_hash,
            car_position,
            car_proposer,
            validators,
            aggregated_signature,
        })
    }

    /// Create from attestations with proposer's self-attestation included
    ///
    /// This method ensures the proposer's own attestation is included in the
    /// aggregated signature, which is required for correct verification.
    /// Per FR-002: "Self-attestation counts as 1 (implicit)" - the proposer
    /// must create and include their own attestation signature.
    ///
    /// # Arguments
    /// * `attestations` - External attestations (from other validators)
    /// * `self_attestation` - Proposer's own attestation for their Car
    /// * `self_index` - Proposer's validator index
    /// * `validator_count` - Total validator count for bitmap sizing
    pub fn aggregate_with_self(
        attestations: &[(Attestation, usize)], // (attestation, validator_index)
        self_attestation: &Attestation,
        self_index: usize,
        validator_count: usize,
    ) -> Option<Self> {
        if self_index >= validator_count {
            return None;
        }

        let car_hash = self_attestation.car_hash;
        let car_position = self_attestation.car_position;
        let car_proposer = self_attestation.car_proposer;

        // Build validator bitmap and collect signatures
        let mut validators = bitvec![u8, Lsb0; 0; validator_count];
        let mut sigs: Vec<&BlsSignature> = Vec::with_capacity(attestations.len() + 1);

        // Include proposer's self-attestation FIRST
        validators.set(self_index, true);
        sigs.push(&self_attestation.signature);

        // Add external attestations
        for (att, idx) in attestations {
            if att.car_hash != car_hash {
                return None;
            }
            // Skip if duplicate index (shouldn't happen, but defensive)
            if *idx < validator_count && !validators[*idx] {
                validators.set(*idx, true);
                sigs.push(&att.signature);
            }
        }

        // Aggregate signatures
        let aggregated_signature = BlsAggregateSignature::aggregate(&sigs).ok()?;

        Some(Self {
            car_hash,
            car_position,
            car_proposer,
            validators,
            aggregated_signature,
        })
    }

    /// Verify aggregated signature against public keys
    ///
    /// # Arguments
    /// * `get_pubkey` - Function to get public key by validator index
    pub fn verify<F>(&self, get_pubkey: F) -> bool
    where
        F: Fn(usize) -> Option<BlsPublicKey>,
    {
        // Collect public keys for validators who attested
        let pubkeys: Vec<BlsPublicKey> = self
            .validators
            .iter()
            .enumerate()
            .filter(|(_, set)| **set)
            .filter_map(|(i, _)| get_pubkey(i))
            .collect();

        if pubkeys.is_empty() {
            return false;
        }

        let pubkey_refs: Vec<&BlsPublicKey> = pubkeys.iter().collect();
        let msg = Attestation::signing_bytes(&self.car_hash, self.car_position, &self.car_proposer);

        self.aggregated_signature
            .verify_same_message(&msg, DST_ATTESTATION, &pubkey_refs)
    }

    /// Count of attesters
    pub fn count(&self) -> usize {
        self.validators.count_ones()
    }

    /// Check if validator at index has attested
    pub fn has_attested(&self, index: usize) -> bool {
        self.validators.get(index).map(|b| *b).unwrap_or(false)
    }

    /// Get indices of validators who attested
    pub fn attester_indices(&self) -> Vec<usize> {
        self.validators
            .iter()
            .enumerate()
            .filter(|(_, set)| **set)
            .map(|(i, _)| i)
            .collect()
    }
}

/// Serde support for BitVec
mod bitvec_serde {
    use bitvec::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bitvec: &BitVec<u8, Lsb0>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<u8> = bitvec.as_raw_slice().to_vec();
        let len = bitvec.len();
        (len, bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BitVec<u8, Lsb0>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (len, bytes): (usize, Vec<u8>) = Deserialize::deserialize(deserializer)?;
        let mut bv = BitVec::<u8, Lsb0>::from_vec(bytes);
        bv.truncate(len);
        Ok(bv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    /// Helper to derive ValidatorId from BLS public key (for tests only)
    /// Takes SHA256 hash of pubkey and uses last 20 bytes
    fn validator_id_from_bls_pubkey(pubkey: &cipherbft_crypto::BlsPublicKey) -> ValidatorId {
        let hash = pubkey.hash();
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes.copy_from_slice(&hash[12..32]); // last 20 bytes
        ValidatorId::from_bytes(bytes)
    }

    fn make_test_car(keypair: &BlsKeyPair) -> Car {
        let validator_id = validator_id_from_bls_pubkey(&keypair.public_key);
        let mut car = Car::new(validator_id, 0, vec![], None);
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);
        car
    }

    #[test]
    fn test_attestation_signing_bytes() {
        let car_hash = Hash::compute(b"car");
        let car_position = 42u64;
        let car_proposer = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);

        let bytes = Attestation::signing_bytes(&car_hash, car_position, &car_proposer);
        assert_eq!(bytes.len(), 60); // 32 + 8 + 20
    }

    #[test]
    fn test_attestation_signing_bytes_deterministic() {
        let car_hash = Hash::compute(b"car");
        let car_position = 10u64;
        let car_proposer = ValidatorId::from_bytes([2u8; VALIDATOR_ID_SIZE]);

        let bytes1 = Attestation::signing_bytes(&car_hash, car_position, &car_proposer);
        let bytes2 = Attestation::signing_bytes(&car_hash, car_position, &car_proposer);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_attestation_sign_verify() {
        let proposer_kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let attester_kp = BlsKeyPair::generate(&mut rand::thread_rng());

        let car = make_test_car(&proposer_kp);
        let attester_id = validator_id_from_bls_pubkey(&attester_kp.public_key);

        let mut att = Attestation::from_car(&car, attester_id);
        let signing_bytes = att.get_signing_bytes();
        att.signature = attester_kp.sign_attestation(&signing_bytes);

        assert!(att.verify(&attester_kp.public_key));
    }

    #[test]
    fn test_aggregated_attestation() {
        let proposer_kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let car = make_test_car(&proposer_kp);

        // Create 5 attesters
        let attesters: Vec<BlsKeyPair> = (0..5)
            .map(|_| BlsKeyPair::generate(&mut rand::thread_rng()))
            .collect();

        // Create attestations with indices
        let attestations: Vec<(Attestation, usize)> = attesters
            .iter()
            .enumerate()
            .map(|(idx, kp)| {
                let attester_id = validator_id_from_bls_pubkey(&kp.public_key);
                let mut att = Attestation::from_car(&car, attester_id);
                let signing_bytes = att.get_signing_bytes();
                att.signature = kp.sign_attestation(&signing_bytes);
                (att, idx)
            })
            .collect();

        // Aggregate
        let agg = AggregatedAttestation::aggregate_with_indices(&attestations, 10).unwrap();

        assert_eq!(agg.count(), 5);

        // Verify with public key lookup
        let pubkeys: Vec<BlsPublicKey> = attesters.iter().map(|kp| kp.public_key.clone()).collect();
        assert!(agg.verify(|idx| pubkeys.get(idx).cloned()));
    }

    #[test]
    fn test_attester_indices() {
        // Create a test car to attest
        let proposer_kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let car = make_test_car(&proposer_kp);

        // Create attestations at specific indices (1, 3, 7)
        let attester_indices = [1usize, 3, 7];
        let attestations_with_indices: Vec<(Attestation, usize)> = attester_indices
            .iter()
            .map(|&idx| {
                let kp = BlsKeyPair::generate(&mut rand::thread_rng());
                let attester_id = validator_id_from_bls_pubkey(&kp.public_key);
                let mut att = Attestation::from_car(&car, attester_id);
                att.signature = kp.sign_attestation(&att.get_signing_bytes());
                (att, idx)
            })
            .collect();

        let agg = AggregatedAttestation::aggregate_with_indices(&attestations_with_indices, 10)
            .expect("aggregation should succeed");

        assert_eq!(agg.attester_indices(), vec![1, 3, 7]);
        assert!(agg.has_attested(1));
        assert!(!agg.has_attested(2));
    }

    #[test]
    fn test_aggregate_with_self() {
        let proposer_kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let car = make_test_car(&proposer_kp);

        // Create proposer's self-attestation
        let proposer_id = validator_id_from_bls_pubkey(&proposer_kp.public_key);
        let mut self_att = Attestation::from_car(&car, proposer_id);
        let self_signing_bytes = self_att.get_signing_bytes();
        self_att.signature = proposer_kp.sign_attestation(&self_signing_bytes);

        // Create 2 external attesters
        let attesters: Vec<BlsKeyPair> = (0..2)
            .map(|_| BlsKeyPair::generate(&mut rand::thread_rng()))
            .collect();

        // Create external attestations with indices (proposer is index 0, attesters are 1, 2)
        let attestations: Vec<(Attestation, usize)> = attesters
            .iter()
            .enumerate()
            .map(|(idx, kp)| {
                let attester_id = validator_id_from_bls_pubkey(&kp.public_key);
                let mut att = Attestation::from_car(&car, attester_id);
                let signing_bytes = att.get_signing_bytes();
                att.signature = kp.sign_attestation(&signing_bytes);
                (att, idx + 1) // indices 1, 2 for external attesters
            })
            .collect();

        // Aggregate with self-attestation
        let agg = AggregatedAttestation::aggregate_with_self(
            &attestations,
            &self_att,
            0, // proposer is index 0
            10,
        )
        .unwrap();

        // Verify count includes self + 2 external
        assert_eq!(agg.count(), 3);

        // Verify bitmap
        assert!(agg.has_attested(0)); // proposer
        assert!(agg.has_attested(1)); // attester 1
        assert!(agg.has_attested(2)); // attester 2
        assert!(!agg.has_attested(3)); // not attested

        // Build public key lookup (proposer at 0, attesters at 1, 2)
        let mut pubkeys: Vec<BlsPublicKey> = Vec::with_capacity(10);
        pubkeys.push(proposer_kp.public_key.clone());
        for kp in &attesters {
            pubkeys.push(kp.public_key.clone());
        }

        // Verify the aggregated signature
        assert!(agg.verify(|idx| pubkeys.get(idx).cloned()));
    }

    #[test]
    fn test_aggregate_with_self_invalid_index() {
        let proposer_kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let car = make_test_car(&proposer_kp);

        let proposer_id = validator_id_from_bls_pubkey(&proposer_kp.public_key);
        let mut self_att = Attestation::from_car(&car, proposer_id);
        self_att.signature = proposer_kp.sign_attestation(&self_att.get_signing_bytes());

        // Try with invalid self_index (>= validator_count)
        let result = AggregatedAttestation::aggregate_with_self(
            &[],
            &self_att,
            10, // invalid: >= validator_count
            10,
        );

        assert!(result.is_none());
    }
}
