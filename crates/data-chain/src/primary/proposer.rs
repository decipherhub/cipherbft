//! Car proposer for Primary process
//!
//! Responsible for creating and signing Cars from pending batch digests.

use crate::batch::BatchDigest;
use crate::car::Car;
use crate::error::DclError;
use cipherbft_crypto::{BlsKeyPair, BlsSecretKey};
use cipherbft_types::{Hash, ValidatorId};

/// Car proposer creates new Cars from batch digests
pub struct Proposer {
    /// Our validator identity
    validator_id: ValidatorId,
    /// BLS key pair for signing
    keypair: BlsKeyPair,
    /// Maximum consecutive empty Cars allowed
    max_empty_cars: u32,
}

impl Proposer {
    /// Create a new Proposer
    pub fn new(validator_id: ValidatorId, secret_key: BlsSecretKey, max_empty_cars: u32) -> Self {
        let keypair = BlsKeyPair::from_secret_key(secret_key);
        Self {
            validator_id,
            keypair,
            max_empty_cars,
        }
    }

    /// Create a new Car from pending batch digests
    ///
    /// # Arguments
    /// * `position` - Position in our lane (should be last_position + 1)
    /// * `batch_digests` - Batch digests to include (will be sorted by worker_id)
    /// * `parent_ref` - Hash of previous Car (None for position 0)
    /// * `empty_car_count` - Current consecutive empty car count
    ///
    /// # Returns
    /// * `Ok(Some(Car))` - Successfully created Car
    /// * `Ok(None)` - Cannot create empty Car (limit reached)
    /// * `Err(_)` - Invalid state
    pub fn create_car(
        &self,
        position: u64,
        mut batch_digests: Vec<BatchDigest>,
        parent_ref: Option<Hash>,
        empty_car_count: u32,
    ) -> Result<Option<Car>, DclError> {
        // Validate position 0 has no parent
        if position == 0 && parent_ref.is_some() {
            return Err(DclError::Config(
                "position 0 cannot have parent_ref".to_string(),
            ));
        }

        // Validate non-zero position has parent
        if position > 0 && parent_ref.is_none() {
            return Err(DclError::Config(
                "position > 0 must have parent_ref".to_string(),
            ));
        }

        // Check empty car policy
        if batch_digests.is_empty() {
            if empty_car_count >= self.max_empty_cars {
                // Cannot create another empty Car
                return Ok(None);
            }
        }

        // Sort batch digests by worker_id for determinism
        batch_digests.sort_by_key(|d| d.worker_id);

        // Create unsigned Car
        let mut car = Car::new(self.validator_id, position, batch_digests, parent_ref);

        // Sign the Car
        let signing_bytes = car.signing_bytes();
        car.signature = self.keypair.sign_car(&signing_bytes);

        Ok(Some(car))
    }

    /// Verify a Car signature (for received Cars)
    pub fn verify_car(&self, car: &Car, public_key: &cipherbft_crypto::BlsPublicKey) -> bool {
        car.verify(public_key)
    }

    /// Get our validator ID
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Get our public key
    pub fn public_key(&self) -> &cipherbft_crypto::BlsPublicKey {
        &self.keypair.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::BlsKeyPair;

    fn make_proposer() -> (Proposer, BlsKeyPair) {
        let keypair = BlsKeyPair::generate(&mut rand::thread_rng());
        let validator_id = ValidatorId::from_bytes(keypair.public_key.hash());
        let proposer = Proposer::new(validator_id, keypair.secret_key.clone(), 3);
        (proposer, keypair)
    }

    fn make_digest(worker_id: u8) -> BatchDigest {
        BatchDigest::new(worker_id, Hash::compute(&[worker_id]), 10, 100)
    }

    #[test]
    fn test_create_first_car() {
        let (proposer, keypair) = make_proposer();

        let car = proposer
            .create_car(0, vec![make_digest(0)], None, 0)
            .unwrap()
            .unwrap();

        assert_eq!(car.position, 0);
        assert!(car.parent_ref.is_none());
        assert!(car.verify(&keypair.public_key));
    }

    #[test]
    fn test_create_subsequent_car() {
        let (proposer, keypair) = make_proposer();

        // First car
        let car1 = proposer
            .create_car(0, vec![make_digest(0)], None, 0)
            .unwrap()
            .unwrap();

        // Second car with parent ref
        let car2 = proposer
            .create_car(1, vec![make_digest(1)], Some(car1.hash()), 0)
            .unwrap()
            .unwrap();

        assert_eq!(car2.position, 1);
        assert_eq!(car2.parent_ref, Some(car1.hash()));
        assert!(car2.verify(&keypair.public_key));
    }

    #[test]
    fn test_batch_digests_sorted() {
        let (proposer, _) = make_proposer();

        // Provide unsorted digests
        let digests = vec![make_digest(2), make_digest(0), make_digest(1)];

        let car = proposer.create_car(0, digests, None, 0).unwrap().unwrap();

        // Should be sorted by worker_id
        assert!(car.is_sorted());
        assert_eq!(car.batch_digests[0].worker_id, 0);
        assert_eq!(car.batch_digests[1].worker_id, 1);
        assert_eq!(car.batch_digests[2].worker_id, 2);
    }

    #[test]
    fn test_empty_car_policy() {
        let (proposer, _) = make_proposer();

        // Can create up to 3 empty cars
        assert!(proposer.create_car(0, vec![], None, 0).unwrap().is_some());
        assert!(proposer
            .create_car(1, vec![], Some(Hash::compute(b"p")), 1)
            .unwrap()
            .is_some());
        assert!(proposer
            .create_car(2, vec![], Some(Hash::compute(b"p")), 2)
            .unwrap()
            .is_some());

        // 4th empty car should return None
        assert!(proposer
            .create_car(3, vec![], Some(Hash::compute(b"p")), 3)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_invalid_first_car_with_parent() {
        let (proposer, _) = make_proposer();

        let result = proposer.create_car(0, vec![], Some(Hash::compute(b"invalid")), 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_subsequent_car_without_parent() {
        let (proposer, _) = make_proposer();

        let result = proposer.create_car(5, vec![], None, 0);
        assert!(result.is_err());
    }
}
