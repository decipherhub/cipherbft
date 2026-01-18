use std::fmt::{Debug, Display};

use cipherbft_crypto::Ed25519PublicKey;
use cipherbft_types::ValidatorId;
use serde::{Deserialize, Deserializer, Serialize};

#[cfg(feature = "malachite")]
use informalsystems_malachitebft_core_types::{
    Address as MalachiteAddress, Validator as MalachiteValidator,
    ValidatorSet as MalachiteValidatorSet, VotingPower,
};

use crate::error::MAX_VALIDATORS;
use crate::signing::ConsensusPublicKey;

/// Consensus address wrapper (Ed25519-derived validator ID).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConsensusAddress(pub ValidatorId);

impl Debug for ConsensusAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConsensusAddress({})", self.0)
    }
}

impl Display for ConsensusAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "malachite")]
impl MalachiteAddress for ConsensusAddress {}

/// Validator entry with voting power and public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusValidator {
    pub address: ConsensusAddress,
    pub public_key: ConsensusPublicKey,
    pub voting_power: u64,
}

impl ConsensusValidator {
    pub fn new(address: ValidatorId, public_key: Ed25519PublicKey, voting_power: u64) -> Self {
        Self {
            address: ConsensusAddress(address),
            public_key: ConsensusPublicKey(public_key),
            voting_power,
        }
    }
}

/// Deterministic validator set (sorted).
///
/// # Security
///
/// This type implements bounded deserialization to prevent OOM attacks.
/// When deserializing, the validator count is checked against [`MAX_VALIDATORS`]
/// before any memory allocation occurs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusValidatorSet {
    #[serde(deserialize_with = "deserialize_bounded_validators")]
    validators: Vec<ConsensusValidator>,
}

/// Custom deserializer that enforces MAX_VALIDATORS limit to prevent OOM attacks.
///
/// This function intercepts the deserialization of the validators vector and
/// checks the length before allocating memory.
fn deserialize_bounded_validators<'de, D>(
    deserializer: D,
) -> Result<Vec<ConsensusValidator>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{SeqAccess, Visitor};

    struct BoundedVecVisitor;

    impl<'de> Visitor<'de> for BoundedVecVisitor {
        type Value = Vec<ConsensusValidator>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence of at most {} validators",
                MAX_VALIDATORS
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Check size hint if available to reject early
            if let Some(size) = seq.size_hint() {
                if size > MAX_VALIDATORS {
                    return Err(serde::de::Error::custom(format!(
                        "validator set size {} exceeds maximum of {}",
                        size, MAX_VALIDATORS
                    )));
                }
            }

            // Allocate with bounded capacity
            let capacity = seq.size_hint().unwrap_or(0).min(MAX_VALIDATORS);
            let mut validators = Vec::with_capacity(capacity);

            while let Some(validator) = seq.next_element()? {
                if validators.len() >= MAX_VALIDATORS {
                    return Err(serde::de::Error::custom(format!(
                        "validator set size exceeds maximum of {}",
                        MAX_VALIDATORS
                    )));
                }
                validators.push(validator);
            }

            Ok(validators)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor)
}

impl ConsensusValidatorSet {
    /// Build from an unsorted validator list.
    pub fn new(mut validators: Vec<ConsensusValidator>) -> Self {
        // Sort descending by power, then ascending by address (per CometBFT rules).
        validators.sort_by(|a, b| {
            b.voting_power
                .cmp(&a.voting_power)
                .then_with(|| a.address.cmp(&b.address))
        });
        Self { validators }
    }

    /// Append another validator (re-sorts internally).
    pub fn push(&mut self, validator: ConsensusValidator) {
        self.validators.push(validator);
        self.validators.sort_by(|a, b| {
            b.voting_power
                .cmp(&a.voting_power)
                .then_with(|| a.address.cmp(&b.address))
        });
    }

    /// Accessor for underlying list.
    pub fn as_slice(&self) -> &[ConsensusValidator] {
        &self.validators
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if the validator set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}

#[cfg(feature = "malachite")]
impl MalachiteValidatorSet<crate::context::CipherBftContext> for ConsensusValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }

    fn total_voting_power(&self) -> VotingPower {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    fn get_by_address(
        &self,
        address: &crate::context::CipherBftContextAddress,
    ) -> Option<&crate::context::CipherBftContextValidator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    fn get_by_index(&self, index: usize) -> Option<&crate::context::CipherBftContextValidator> {
        self.validators.get(index)
    }
}

#[cfg(feature = "malachite")]
impl MalachiteValidator<crate::context::CipherBftContext> for ConsensusValidator {
    fn address(&self) -> &crate::context::CipherBftContextAddress {
        &self.address
    }

    fn public_key(
        &self,
    ) -> &informalsystems_malachitebft_core_types::PublicKey<crate::context::CipherBftContext> {
        &self.public_key
    }

    fn voting_power(&self) -> VotingPower {
        self.voting_power
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_crypto::Ed25519KeyPair;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    fn make_test_validator(seed: u8) -> ConsensusValidator {
        let mut rng = rand::thread_rng();
        let keypair = Ed25519KeyPair::generate(&mut rng);
        ConsensusValidator::new(
            keypair.validator_id(),
            keypair.public_key,
            seed as u64 * 100,
        )
    }

    #[test]
    fn test_validator_set_serialization_roundtrip() {
        let validators = vec![make_test_validator(1), make_test_validator(2)];
        let set = ConsensusValidatorSet::new(validators);

        // Serialize and deserialize
        let serialized = bincode::serialize(&set).expect("serialization should succeed");
        let deserialized: ConsensusValidatorSet =
            bincode::deserialize(&serialized).expect("deserialization should succeed");

        assert_eq!(set.len(), deserialized.len());
    }

    #[test]
    fn test_validator_set_json_roundtrip() {
        let validators = vec![make_test_validator(1), make_test_validator(2)];
        let set = ConsensusValidatorSet::new(validators);

        // JSON roundtrip
        let json = serde_json::to_string(&set).expect("JSON serialization should succeed");
        let deserialized: ConsensusValidatorSet =
            serde_json::from_str(&json).expect("JSON deserialization should succeed");

        assert_eq!(set.len(), deserialized.len());
    }

    #[test]
    fn test_bounded_deserialization_accepts_valid_size() {
        // Create a small valid set
        let validators: Vec<ConsensusValidator> = (0..10).map(make_test_validator).collect();
        let set = ConsensusValidatorSet::new(validators);

        let serialized = bincode::serialize(&set).expect("serialization should succeed");
        let result: Result<ConsensusValidatorSet, _> = bincode::deserialize(&serialized);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 10);
    }

    #[test]
    fn test_empty_validator_set() {
        let set = ConsensusValidatorSet::default();
        assert!(set.is_empty());

        let serialized = bincode::serialize(&set).expect("serialization should succeed");
        let deserialized: ConsensusValidatorSet =
            bincode::deserialize(&serialized).expect("deserialization should succeed");

        assert!(deserialized.is_empty());
    }

    #[test]
    fn test_consensus_address_serialization() {
        let addr = ConsensusAddress(ValidatorId::from_bytes([0xab; VALIDATOR_ID_SIZE]));

        let json = serde_json::to_string(&addr).expect("serialization should succeed");
        let deserialized: ConsensusAddress =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(addr, deserialized);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_max_validators_constant_is_reasonable() {
        // Ensure MAX_VALIDATORS is set to a reasonable value
        assert!(
            MAX_VALIDATORS >= 100,
            "MAX_VALIDATORS should be at least 100"
        );
        assert!(
            MAX_VALIDATORS <= 100_000,
            "MAX_VALIDATORS should not exceed 100,000"
        );
    }
}
