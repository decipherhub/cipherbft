//! Car (Certified Available Record) for DCL
//!
//! A Car represents a validator's contribution containing batch digests.
//! Cars form a chain per validator via parent_ref linking.

use crate::batch::BatchDigest;
use cipherbft_crypto::BlsSignature;
use cipherbft_types::{Hash, ValidatorId};
use serde::{Deserialize, Serialize};

/// A Car represents a validator's contribution to a consensus height
///
/// Cars contain:
/// - Batch digests from Workers (transaction metadata)
/// - Position in the validator's lane (monotonically increasing)
/// - Parent reference for chain integrity
/// - BLS12-381 signature for authenticity
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Car {
    /// Validator who created this Car
    pub proposer: ValidatorId,
    /// Position in this validator's lane (monotonically increasing, starts at 0)
    pub position: u64,
    /// Batch digests from Workers (must be sorted by worker_id)
    pub batch_digests: Vec<BatchDigest>,
    /// Hash of previous Car in this validator's lane (None for position 0)
    pub parent_ref: Option<Hash>,
    /// BLS12-381 signature over canonical Car contents
    pub signature: BlsSignature,
}

impl Car {
    /// Create a new Car (unsigned - call sign() after)
    pub fn new(
        proposer: ValidatorId,
        position: u64,
        batch_digests: Vec<BatchDigest>,
        parent_ref: Option<Hash>,
    ) -> Self {
        Self {
            proposer,
            position,
            batch_digests,
            parent_ref,
            signature: BlsSignature::default(),
        }
    }

    /// Canonical bytes for signing
    ///
    /// Order: proposer (32) || position (8) || parent_ref (1 + 0/32) || sorted_batch_digests
    ///
    /// This order ensures:
    /// 1. Validator identity comes first
    /// 2. Position enables sequence validation
    /// 3. Parent ref enables chain integrity
    /// 4. Batch digests are sorted by worker_id for determinism
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        // Proposer (32 bytes)
        buf.extend_from_slice(self.proposer.as_bytes());

        // Position (8 bytes, little-endian)
        buf.extend_from_slice(&self.position.to_le_bytes());

        // Parent ref (1 + 0/32 bytes)
        match &self.parent_ref {
            None => buf.push(0x00),
            Some(hash) => {
                buf.push(0x01);
                buf.extend_from_slice(hash.as_bytes());
            }
        }

        // Sorted batch digests
        let mut sorted_digests = self.batch_digests.clone();
        sorted_digests.sort_by_key(|d| d.worker_id);
        for digest in sorted_digests {
            buf.extend_from_slice(&digest.to_bytes());
        }

        buf
    }

    /// Compute Car hash (for attestation and parent_ref)
    pub fn hash(&self) -> Hash {
        Hash::compute(&self.signing_bytes())
    }

    /// Check if this is an empty Car (heartbeat)
    pub fn is_empty(&self) -> bool {
        self.batch_digests.is_empty()
    }

    /// Get total transaction count across all batches
    pub fn tx_count(&self) -> u32 {
        self.batch_digests.iter().map(|d| d.tx_count).sum()
    }

    /// Get total byte size across all batches
    pub fn total_bytes(&self) -> u32 {
        self.batch_digests.iter().map(|d| d.byte_size).sum()
    }

    /// Validate batch_digests are sorted by worker_id
    pub fn is_sorted(&self) -> bool {
        self.batch_digests
            .windows(2)
            .all(|w| w[0].worker_id <= w[1].worker_id)
    }

    /// Verify the Car signature
    pub fn verify(&self, public_key: &cipherbft_crypto::BlsPublicKey) -> bool {
        let signing_bytes = self.signing_bytes();
        public_key.verify(&signing_bytes, cipherbft_crypto::DST_CAR, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;

    fn make_test_digest(worker_id: u8) -> BatchDigest {
        BatchDigest {
            worker_id,
            digest: Hash::compute(&[worker_id]),
            tx_count: 10,
            byte_size: 100,
        }
    }

    #[test]
    fn test_signing_bytes_deterministic() {
        let car = Car::new(
            ValidatorId::from_bytes([1u8; 32]),
            42,
            vec![make_test_digest(1), make_test_digest(0)], // Unsorted
            None,
        );

        let bytes1 = car.signing_bytes();
        let bytes2 = car.signing_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_signing_bytes_sorts_digests() {
        let car1 = Car::new(
            ValidatorId::from_bytes([1u8; 32]),
            0,
            vec![
                make_test_digest(2),
                make_test_digest(0),
                make_test_digest(1),
            ],
            None,
        );

        let car2 = Car::new(
            ValidatorId::from_bytes([1u8; 32]),
            0,
            vec![
                make_test_digest(0),
                make_test_digest(1),
                make_test_digest(2),
            ],
            None,
        );

        // Both should produce same signing bytes due to sorting
        assert_eq!(car1.signing_bytes(), car2.signing_bytes());
    }

    #[test]
    fn test_car_hash_deterministic() {
        let car = Car::new(
            ValidatorId::from_bytes([1u8; 32]),
            5,
            vec![make_test_digest(0)],
            Some(Hash::compute(b"parent")),
        );

        let h1 = car.hash();
        let h2 = car.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_empty_car() {
        let car = Car::new(ValidatorId::from_bytes([1u8; 32]), 0, vec![], None);
        assert!(car.is_empty());
        assert_eq!(car.tx_count(), 0);
        assert_eq!(car.total_bytes(), 0);
    }

    #[test]
    fn test_car_sign_verify() {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let validator_id = ValidatorId::from_bytes(keypair.public_key.hash());

        let mut car = Car::new(validator_id, 0, vec![make_test_digest(0)], None);

        // Sign the car
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);

        // Verify
        assert!(car.verify(&keypair.public_key));
    }

    #[test]
    fn test_parent_ref_affects_hash() {
        let car1 = Car::new(ValidatorId::from_bytes([1u8; 32]), 1, vec![], None);

        let car2 = Car::new(
            ValidatorId::from_bytes([1u8; 32]),
            1,
            vec![],
            Some(Hash::compute(b"parent")),
        );

        assert_ne!(car1.hash(), car2.hash());
    }

    #[test]
    fn test_is_sorted() {
        let sorted_car = Car::new(
            ValidatorId::from_bytes([1u8; 32]),
            0,
            vec![
                make_test_digest(0),
                make_test_digest(1),
                make_test_digest(2),
            ],
            None,
        );
        assert!(sorted_car.is_sorted());

        let unsorted_car = Car::new(
            ValidatorId::from_bytes([1u8; 32]),
            0,
            vec![make_test_digest(2), make_test_digest(0)],
            None,
        );
        assert!(!unsorted_car.is_sorted());
    }
}
