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

    /// Compute deterministic hash for this Cut (for Malachite Value::id())
    ///
    /// CRITICAL: Required for consensus integration. All validators must compute
    /// the same hash for the same Cut to achieve consensus.
    ///
    /// The hash includes:
    /// - Height (8 bytes)
    /// - Number of Cars (4 bytes)
    /// - For each Car in ValidatorId order:
    ///   - Car hash (32 bytes)
    ///   - Car position (8 bytes)
    ///
    /// Note: Attestations are not included in the hash since they are metadata
    /// for verification, not part of the consensus value.
    pub fn hash(&self) -> Hash {
        let mut data = Vec::with_capacity(12 + self.cars.len() * 40);

        // Height
        data.extend_from_slice(&self.height.to_be_bytes());

        // Number of Cars
        data.extend_from_slice(&(self.cars.len() as u32).to_be_bytes());

        // Cars in deterministic order (ValidatorId ascending)
        for (_, car) in self.ordered_cars() {
            // Include Car hash and position
            data.extend_from_slice(car.hash().as_bytes());
            data.extend_from_slice(&car.position.to_be_bytes());
        }

        Hash::compute(&data)
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
        for car in self.cars.values() {
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

    /// Stream this Cut as CutParts for network transmission
    ///
    /// Returns an iterator over CutPart items in order:
    /// 1. Init - metadata
    /// 2. CarData for each Car (in ValidatorId order)
    /// 3. Fin - completion marker with hash
    ///
    /// # Arguments
    /// * `proposer` - The validator proposing this Cut
    /// * `round` - The consensus round
    pub fn stream_parts(
        &self,
        proposer: ValidatorId,
        round: u32,
    ) -> impl Iterator<Item = CutPart> + '_ {
        let init = CutPart::Init {
            height: self.height,
            round,
            proposer,
            car_count: self.cars.len() as u32,
        };

        let car_parts = self.ordered_cars().filter_map(move |(_, car)| {
            let car_hash = car.hash();
            self.attestations.get(&car_hash).map(|att| CutPart::CarData {
                car: car.clone(),
                attestation: att.clone(),
            })
        });

        let fin_hash = self.hash();
        let fin = CutPart::Fin { cut_hash: fin_hash };

        std::iter::once(init)
            .chain(car_parts)
            .chain(std::iter::once(fin))
    }
}

/// Cut streaming part for network transmission
///
/// Cuts are streamed as parts to allow incremental transmission and
/// verification during consensus. Malachite uses this via
/// `NetworkMsg::PublishProposalPart`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CutPart {
    /// Initial metadata - sent first
    Init {
        /// Consensus height
        height: u64,
        /// Consensus round
        round: u32,
        /// Validator proposing this Cut
        proposer: ValidatorId,
        /// Number of Cars in this Cut
        car_count: u32,
    },
    /// Individual Car with its aggregated attestation
    CarData {
        /// The Car
        car: Car,
        /// Aggregated attestation for the Car
        attestation: AggregatedAttestation,
    },
    /// Final part - sent last, contains Cut hash for verification
    Fin {
        /// Hash of the complete Cut (for verification)
        cut_hash: Hash,
    },
}

impl CutPart {
    /// Get the type name for logging/debugging
    pub fn get_type(&self) -> &'static str {
        match self {
            Self::Init { .. } => "init",
            Self::CarData { .. } => "car",
            Self::Fin { .. } => "fin",
        }
    }
}

/// Cut assembly state for receiving streamed parts
///
/// Used by receivers to collect CutParts and assemble the complete Cut.
#[derive(Debug)]
pub struct CutAssembler {
    /// Expected height (from Init)
    height: Option<u64>,
    /// Expected round (from Init)
    round: Option<u32>,
    /// Proposer (from Init)
    proposer: Option<ValidatorId>,
    /// Expected car count (from Init)
    expected_count: Option<u32>,
    /// Cars collected so far
    cars: HashMap<ValidatorId, Car>,
    /// Attestations collected so far
    attestations: HashMap<Hash, AggregatedAttestation>,
    /// Whether we received the Fin part
    received_fin: bool,
    /// Expected hash (from Fin)
    expected_hash: Option<Hash>,
}

impl CutAssembler {
    /// Create a new assembler
    pub fn new() -> Self {
        Self {
            height: None,
            round: None,
            proposer: None,
            expected_count: None,
            cars: HashMap::new(),
            attestations: HashMap::new(),
            received_fin: false,
            expected_hash: None,
        }
    }

    /// Process a received CutPart
    ///
    /// # Returns
    /// - `Ok(Some(Cut))` if all parts received and Cut is valid
    /// - `Ok(None)` if more parts needed
    /// - `Err(_)` if part is invalid or out of order
    pub fn add_part(&mut self, part: CutPart) -> Result<Option<Cut>, CutAssemblyError> {
        match part {
            CutPart::Init {
                height,
                round,
                proposer,
                car_count,
            } => {
                if self.height.is_some() {
                    return Err(CutAssemblyError::DuplicateInit);
                }
                self.height = Some(height);
                self.round = Some(round);
                self.proposer = Some(proposer);
                self.expected_count = Some(car_count);
                Ok(None)
            }
            CutPart::CarData { car, attestation } => {
                if self.height.is_none() {
                    return Err(CutAssemblyError::MissingInit);
                }
                let car_hash = car.hash();
                self.cars.insert(car.proposer, car);
                self.attestations.insert(car_hash, attestation);
                Ok(None)
            }
            CutPart::Fin { cut_hash } => {
                if self.height.is_none() {
                    return Err(CutAssemblyError::MissingInit);
                }
                self.received_fin = true;
                self.expected_hash = Some(cut_hash);

                // Check if we have all parts
                self.try_assemble()
            }
        }
    }

    /// Try to assemble the final Cut
    fn try_assemble(&self) -> Result<Option<Cut>, CutAssemblyError> {
        let Some(height) = self.height else {
            return Ok(None);
        };
        let Some(expected_count) = self.expected_count else {
            return Ok(None);
        };

        if !self.received_fin {
            return Ok(None);
        }

        if self.cars.len() != expected_count as usize {
            return Err(CutAssemblyError::IncompleteCarData {
                expected: expected_count as usize,
                received: self.cars.len(),
            });
        }

        let cut = Cut {
            height,
            cars: self.cars.clone(),
            attestations: self.attestations.clone(),
        };

        // Verify hash
        if let Some(expected_hash) = &self.expected_hash {
            if cut.hash() != *expected_hash {
                return Err(CutAssemblyError::HashMismatch);
            }
        }

        Ok(Some(cut))
    }

    /// Get the proposer if Init has been received
    pub fn proposer(&self) -> Option<ValidatorId> {
        self.proposer
    }

    /// Get progress info
    pub fn progress(&self) -> (usize, Option<u32>) {
        (self.cars.len(), self.expected_count)
    }

    /// Check if assembly is complete
    pub fn is_complete(&self) -> bool {
        self.received_fin
            && self.expected_count.map(|c| c as usize) == Some(self.cars.len())
    }
}

impl Default for CutAssembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors during Cut assembly
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutAssemblyError {
    /// Received Init twice
    DuplicateInit,
    /// Received CarData or Fin before Init
    MissingInit,
    /// Car count doesn't match expected
    IncompleteCarData { expected: usize, received: usize },
    /// Assembled Cut hash doesn't match Fin hash
    HashMismatch,
}

impl std::fmt::Display for CutAssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateInit => write!(f, "received duplicate Init part"),
            Self::MissingInit => write!(f, "received part before Init"),
            Self::IncompleteCarData { expected, received } => {
                write!(f, "car count mismatch: expected {expected}, got {received}")
            }
            Self::HashMismatch => write!(f, "assembled Cut hash doesn't match expected"),
        }
    }
}

impl std::error::Error for CutAssemblyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Attestation;
    use crate::batch::BatchDigest;
    use cipherbft_crypto::BlsKeyPair;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    /// Helper to derive ValidatorId from BLS public key (for tests only)
    fn validator_id_from_bls_pubkey(pubkey: &cipherbft_crypto::BlsPublicKey) -> ValidatorId {
        let hash = pubkey.hash();
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes.copy_from_slice(&hash[12..32]); // last 20 bytes
        ValidatorId::from_bytes(bytes)
    }

    fn make_test_car(keypair: &BlsKeyPair, position: u64) -> Car {
        let validator_id = validator_id_from_bls_pubkey(&keypair.public_key);
        let mut car = Car::new(validator_id, position, vec![], None);
        let signing_bytes = car.signing_bytes();
        car.signature = keypair.sign_car(&signing_bytes);
        car
    }

    /// Create a test attestation from a keypair and car
    fn make_test_attestation(keypair: &BlsKeyPair, car: &Car) -> Attestation {
        let validator_id = validator_id_from_bls_pubkey(&keypair.public_key);
        let mut att = Attestation::from_car(car, validator_id);
        let signing_bytes = att.get_signing_bytes();
        att.signature = keypair.sign_attestation(&signing_bytes);
        att
    }

    /// Create a test aggregated attestation for a car
    fn make_test_agg_attestation(keypair: &BlsKeyPair, car: &Car) -> AggregatedAttestation {
        let att = make_test_attestation(keypair, car);
        AggregatedAttestation::aggregate_with_indices(&[(att, 0)], 4).unwrap()
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
        let validator_id = validator_id_from_bls_pubkey(&kp.public_key);

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
            .map(|i| ValidatorId::from_bytes([i as u8; VALIDATOR_ID_SIZE]))
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
        let validator_id = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);

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
            .map(|i| ValidatorId::from_bytes([i as u8; VALIDATOR_ID_SIZE]))
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

    #[test]
    fn test_cut_hash_determinism() {
        // Create the same Cut twice and verify same hash
        let kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let car = make_test_car(&kp, 0);

        let mut cut1 = Cut::new(1);
        cut1.cars.insert(car.proposer, car.clone());

        let mut cut2 = Cut::new(1);
        cut2.cars.insert(car.proposer, car);

        assert_eq!(cut1.hash(), cut2.hash());
    }

    #[test]
    fn test_cut_hash_different_heights() {
        let kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let car = make_test_car(&kp, 0);

        let mut cut1 = Cut::new(1);
        cut1.cars.insert(car.proposer, car.clone());

        let mut cut2 = Cut::new(2);
        cut2.cars.insert(car.proposer, car);

        // Different heights should produce different hashes
        assert_ne!(cut1.hash(), cut2.hash());
    }

    #[test]
    fn test_cut_hash_different_cars() {
        let kp1 = BlsKeyPair::generate(&mut rand::thread_rng());
        let kp2 = BlsKeyPair::generate(&mut rand::thread_rng());

        let car1 = make_test_car(&kp1, 0);
        let car2 = make_test_car(&kp2, 0);

        let mut cut1 = Cut::new(1);
        cut1.cars.insert(car1.proposer, car1);

        let mut cut2 = Cut::new(1);
        cut2.cars.insert(car2.proposer, car2);

        // Different cars should produce different hashes
        assert_ne!(cut1.hash(), cut2.hash());
    }

    #[test]
    fn test_cut_hash_order_independence() {
        // Hash should be the same regardless of insertion order
        let kp1 = BlsKeyPair::generate(&mut rand::thread_rng());
        let kp2 = BlsKeyPair::generate(&mut rand::thread_rng());
        let kp3 = BlsKeyPair::generate(&mut rand::thread_rng());

        let car1 = make_test_car(&kp1, 0);
        let car2 = make_test_car(&kp2, 0);
        let car3 = make_test_car(&kp3, 0);

        // Insert in one order
        let mut cut1 = Cut::new(1);
        cut1.cars.insert(car1.proposer, car1.clone());
        cut1.cars.insert(car2.proposer, car2.clone());
        cut1.cars.insert(car3.proposer, car3.clone());

        // Insert in different order
        let mut cut2 = Cut::new(1);
        cut2.cars.insert(car3.proposer, car3);
        cut2.cars.insert(car1.proposer, car1);
        cut2.cars.insert(car2.proposer, car2);

        // Hash should be the same (deterministic based on ValidatorId order)
        assert_eq!(cut1.hash(), cut2.hash());
    }

    #[test]
    fn test_cut_hash_empty() {
        let cut = Cut::new(1);
        let hash = cut.hash();

        // Empty cut should still have a valid hash
        assert_ne!(hash, Hash::compute(b""));

        // Different empty cuts at different heights have different hashes
        let cut2 = Cut::new(2);
        assert_ne!(cut.hash(), cut2.hash());
    }

    #[test]
    fn test_cut_part_stream_empty() {
        let cut = Cut::new(1);
        let proposer = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);

        let parts: Vec<_> = cut.stream_parts(proposer, 0).collect();

        // Should have Init and Fin, no CarData
        assert_eq!(parts.len(), 2);

        // Check Init
        match &parts[0] {
            CutPart::Init {
                height,
                round,
                proposer: p,
                car_count,
            } => {
                assert_eq!(*height, 1);
                assert_eq!(*round, 0);
                assert_eq!(*p, proposer);
                assert_eq!(*car_count, 0);
            }
            _ => panic!("expected Init"),
        }

        // Check Fin
        match &parts[1] {
            CutPart::Fin { cut_hash } => {
                assert_eq!(*cut_hash, cut.hash());
            }
            _ => panic!("expected Fin"),
        }
    }

    #[test]
    fn test_cut_part_stream_with_cars() {
        let kp1 = BlsKeyPair::generate(&mut rand::thread_rng());
        let kp2 = BlsKeyPair::generate(&mut rand::thread_rng());

        let car1 = make_test_car(&kp1, 0);
        let car2 = make_test_car(&kp2, 0);

        // Create attestations using helper
        let att1 = make_test_agg_attestation(&kp1, &car1);
        let att2 = make_test_agg_attestation(&kp2, &car2);

        let mut cut = Cut::new(1);
        cut.add_car(car1.clone(), att1);
        cut.add_car(car2.clone(), att2);

        let proposer = ValidatorId::from_bytes([0xabu8; VALIDATOR_ID_SIZE]);
        let parts: Vec<_> = cut.stream_parts(proposer, 5).collect();

        // Should have Init + 2 CarData + Fin
        assert_eq!(parts.len(), 4);

        // Check part types
        assert!(matches!(parts[0], CutPart::Init { .. }));
        assert!(matches!(parts[1], CutPart::CarData { .. }));
        assert!(matches!(parts[2], CutPart::CarData { .. }));
        assert!(matches!(parts[3], CutPart::Fin { .. }));
    }

    #[test]
    fn test_cut_assembler_basic() {
        let kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let car = make_test_car(&kp, 0);
        let att = make_test_agg_attestation(&kp, &car);

        let mut cut = Cut::new(1);
        cut.add_car(car, att);

        let proposer = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);

        // Stream and reassemble
        let mut assembler = CutAssembler::new();
        for part in cut.stream_parts(proposer, 0) {
            if let Ok(Some(assembled)) = assembler.add_part(part) {
                assert_eq!(assembled.hash(), cut.hash());
                assert_eq!(assembled.cars.len(), cut.cars.len());
                return;
            }
        }
        panic!("cut was not assembled");
    }

    #[test]
    fn test_cut_assembler_error_missing_init() {
        let kp = BlsKeyPair::generate(&mut rand::thread_rng());
        let car = make_test_car(&kp, 0);
        let att = make_test_agg_attestation(&kp, &car);

        let mut assembler = CutAssembler::new();

        // Sending CarData before Init should fail
        let result = assembler.add_part(CutPart::CarData {
            car,
            attestation: att,
        });
        assert!(matches!(result, Err(CutAssemblyError::MissingInit)));
    }

    #[test]
    fn test_cut_assembler_error_duplicate_init() {
        let proposer = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);

        let mut assembler = CutAssembler::new();

        // First Init should succeed
        let result = assembler.add_part(CutPart::Init {
            height: 1,
            round: 0,
            proposer,
            car_count: 0,
        });
        assert!(result.is_ok());

        // Second Init should fail
        let result = assembler.add_part(CutPart::Init {
            height: 2,
            round: 1,
            proposer,
            car_count: 0,
        });
        assert!(matches!(result, Err(CutAssemblyError::DuplicateInit)));
    }

    #[test]
    fn test_cut_assembler_hash_mismatch() {
        let proposer = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);

        let mut assembler = CutAssembler::new();

        assembler
            .add_part(CutPart::Init {
                height: 1,
                round: 0,
                proposer,
                car_count: 0,
            })
            .unwrap();

        // Send Fin with wrong hash
        let result = assembler.add_part(CutPart::Fin {
            cut_hash: Hash::compute(b"wrong"),
        });
        assert!(matches!(result, Err(CutAssemblyError::HashMismatch)));
    }

    #[test]
    fn test_cut_part_get_type() {
        let proposer = ValidatorId::from_bytes([1u8; VALIDATOR_ID_SIZE]);

        let init = CutPart::Init {
            height: 1,
            round: 0,
            proposer,
            car_count: 0,
        };
        assert_eq!(init.get_type(), "init");

        let fin = CutPart::Fin {
            cut_hash: Hash::compute(b"test"),
        };
        assert_eq!(fin.get_type(), "fin");
    }
}
