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
    /// Format: car_hash (32) || car_position (8) || car_proposer (32) = 72 bytes
    pub fn signing_bytes(
        car_hash: &Hash,
        car_position: u64,
        car_proposer: &ValidatorId,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(72);
        buf.extend_from_slice(car_hash.as_bytes()); // 32 bytes
        buf.extend_from_slice(&car_position.to_le_bytes()); // 8 bytes
        buf.extend_from_slice(car_proposer.as_bytes()); // 32 bytes
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
    /// Create from individual attestations
    ///
    /// # Panics
    /// Panics if attestations is empty or attestations have different car_hash
    pub fn aggregate(attestations: &[Attestation], validator_count: usize) -> Option<Self> {
        if attestations.is_empty() {
            return None;
        }

        let first = &attestations[0];
        let car_hash = first.car_hash;
        let car_position = first.car_position;
        let car_proposer = first.car_proposer;

        // Verify all attestations are for the same Car
        for att in attestations {
            if att.car_hash != car_hash {
                return None;
            }
        }

        // Build validator bitmap and collect signatures
        // Note: Without index mapping, we cannot populate the bitmap correctly
        // Use aggregate_with_indices() for proper bitmap population
        let validators = bitvec![u8, Lsb0; 0; validator_count];
        let mut sigs: Vec<&BlsSignature> = Vec::with_capacity(attestations.len());

        for att in attestations {
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

    fn make_test_car(keypair: &BlsKeyPair) -> Car {
        let validator_id = ValidatorId::from_bytes(keypair.public_key.hash());
        let mut car = Car::new(validator_id, 0, vec![], None);
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);
        car
    }

    #[test]
    fn test_attestation_signing_bytes() {
        let car_hash = Hash::compute(b"car");
        let car_position = 42u64;
        let car_proposer = ValidatorId::from_bytes([1u8; 32]);

        let bytes = Attestation::signing_bytes(&car_hash, car_position, &car_proposer);
        assert_eq!(bytes.len(), 72);
    }

    #[test]
    fn test_attestation_signing_bytes_deterministic() {
        let car_hash = Hash::compute(b"car");
        let car_position = 10u64;
        let car_proposer = ValidatorId::from_bytes([2u8; 32]);

        let bytes1 = Attestation::signing_bytes(&car_hash, car_position, &car_proposer);
        let bytes2 = Attestation::signing_bytes(&car_hash, car_position, &car_proposer);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_attestation_sign_verify() {
        let proposer_kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let attester_kp = BlsKeyPair::generate(&mut rand::thread_rng());

        let car = make_test_car(&proposer_kp);
        let attester_id = ValidatorId::from_bytes(attester_kp.public_key.hash());

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
                let attester_id = ValidatorId::from_bytes(kp.public_key.hash());
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
        let mut validators = bitvec![u8, Lsb0; 0; 10];
        validators.set(1, true);
        validators.set(3, true);
        validators.set(7, true);

        let agg = AggregatedAttestation {
            car_hash: Hash::ZERO,
            car_position: 0,
            car_proposer: ValidatorId::ZERO,
            validators,
            aggregated_signature: {
                let kp = BlsKeyPair::generate(&mut rand::thread_rng());
                BlsAggregateSignature::from_signature(&kp.sign_attestation(b"dummy"))
            },
        };

        assert_eq!(agg.attester_indices(), vec![1, 3, 7]);
        assert!(agg.has_attested(1));
        assert!(!agg.has_attested(2));
    }
}
