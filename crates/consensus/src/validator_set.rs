use std::fmt::{Debug, Display};

use cipherbft_crypto::Ed25519PublicKey;
use cipherbft_types::ValidatorId;

#[cfg(feature = "malachite")]
use informalsystems_malachitebft_core_types::{Address as MalachiteAddress, Validator as MalachiteValidator, ValidatorSet as MalachiteValidatorSet, VotingPower};

use crate::signing::ConsensusPublicKey;

/// Consensus address wrapper (Ed25519-derived validator ID).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConsensusValidatorSet {
    validators: Vec<ConsensusValidator>,
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

    fn get_by_index(
        &self,
        index: usize,
    ) -> Option<&crate::context::CipherBftContextValidator> {
        self.validators.get(index)
    }
}

#[cfg(feature = "malachite")]
impl MalachiteValidator<crate::context::CipherBftContext> for ConsensusValidator {
    fn address(&self) -> &crate::context::CipherBftContextAddress {
        &self.address
    }

    fn public_key(&self) -> &informalsystems_malachitebft_core_types::PublicKey<crate::context::CipherBftContext> {
        &self.public_key
    }

    fn voting_power(&self) -> VotingPower {
        self.voting_power
    }
}
