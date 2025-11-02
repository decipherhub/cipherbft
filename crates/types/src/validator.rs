//! Validator types and leader selection.
//!
//! Implements weighted round-robin leader selection algorithm
//! based on proposer priority to ensure fair block proposal rotation.

use crate::Height;
use serde::{Deserialize, Serialize};

/// A validator in the consensus network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Validator {
    /// Validator address (typically hash of public key).
    pub address: Vec<u8>,
    /// Public key for signature verification.
    pub public_key: Vec<u8>,
    /// Voting power (stake weight).
    pub voting_power: u64,
    /// Proposer priority for weighted round-robin leader selection.
    pub proposer_priority: i64,
}

impl Validator {
    /// Create a new validator.
    pub fn new(address: Vec<u8>, public_key: Vec<u8>, voting_power: u64) -> Self {
        Self {
            address,
            public_key,
            voting_power,
            proposer_priority: 0,
        }
    }

    /// Create validator with specific priority (used for testing).
    pub fn with_priority(
        address: Vec<u8>,
        public_key: Vec<u8>,
        voting_power: u64,
        proposer_priority: i64,
    ) -> Self {
        Self {
            address,
            public_key,
            voting_power,
            proposer_priority,
        }
    }
}

/// Set of validators.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// List of validators.
    pub validators: Vec<Validator>,
    /// Total voting power.
    pub total_voting_power: u64,
    /// Height this validator set is active at.
    pub height: Height,
}

impl ValidatorSet {
    /// Create a new validator set.
    ///
    /// # Errors
    ///
    /// Returns an error if the validator set is empty or if total voting power is zero.
    pub fn new(validators: Vec<Validator>, height: Height) -> Result<Self, ValidatorSetError> {
        if validators.is_empty() {
            return Err(ValidatorSetError::EmptyValidatorSet);
        }

        let total_voting_power: u64 = validators.iter().map(|v| v.voting_power).sum();

        if total_voting_power == 0 {
            return Err(ValidatorSetError::ZeroVotingPower);
        }

        Ok(Self {
            validators,
            total_voting_power,
            height,
        })
    }

    /// Calculate quorum (2f+1) voting power needed for consensus.
    pub fn quorum(&self) -> u64 {
        let f = (self.total_voting_power - 1) / 3;
        2 * f + 1
    }

    /// Check if address is in validator set.
    pub fn contains(&self, address: &[u8]) -> bool {
        self.validators.iter().any(|v| v.address == address)
    }

    /// Get validator by address.
    pub fn get_validator(&self, address: &[u8]) -> Option<&Validator> {
        self.validators.iter().find(|v| v.address == address)
    }

    /// Get the current proposer (validator with highest priority).
    pub fn proposer(&self) -> &Validator {
        self.validators
            .iter()
            .max_by_key(|v| v.proposer_priority)
            .expect("validator set cannot be empty")
    }

    /// Increment proposer priorities for next round (weighted round-robin).
    ///
    /// Algorithm:
    /// 1. Each validator's priority increases by their voting power
    /// 2. The selected proposer's priority decreases by total voting power
    /// 3. This ensures fair rotation proportional to stake
    pub fn increment_proposer_priority(&mut self) {
        // Get current proposer before incrementing
        let proposer_address = self.proposer().address.clone();

        // Increment all priorities by voting power
        for validator in &mut self.validators {
            validator.proposer_priority += validator.voting_power as i64;
        }

        // Decrease proposer's priority by total voting power
        for validator in &mut self.validators {
            if validator.address == proposer_address {
                validator.proposer_priority -= self.total_voting_power as i64;
                break;
            }
        }
    }

    /// Reset all proposer priorities to initial state.
    ///
    /// Useful when validator set changes or for testing.
    pub fn reset_proposer_priorities(&mut self) {
        for validator in &mut self.validators {
            validator.proposer_priority = 0;
        }
    }

    /// Calculate total voting power of a subset of validators.
    pub fn voting_power_of(&self, addresses: &[Vec<u8>]) -> u64 {
        self.validators
            .iter()
            .filter(|v| addresses.contains(&v.address))
            .map(|v| v.voting_power)
            .sum()
    }

    /// Check if the given addresses represent a quorum.
    pub fn has_quorum(&self, addresses: &[Vec<u8>]) -> bool {
        self.voting_power_of(addresses) >= self.quorum()
    }
}

/// Validator set error type.
#[derive(Debug, thiserror::Error)]
pub enum ValidatorSetError {
    /// Validator set cannot be empty.
    #[error("Validator set cannot be empty")]
    EmptyValidatorSet,
    /// Total voting power cannot be zero.
    #[error("Total voting power cannot be zero")]
    ZeroVotingPower,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validators() -> Vec<Validator> {
        vec![
            Validator::new(vec![1], vec![1; 32], 10),
            Validator::new(vec![2], vec![2; 32], 10),
            Validator::new(vec![3], vec![3; 32], 10),
            Validator::new(vec![4], vec![4; 32], 10),
        ]
    }

    #[test]
    fn test_validator_creation() {
        let validator = Validator::new(vec![1, 2, 3], vec![4, 5, 6], 100);
        assert_eq!(validator.address, vec![1, 2, 3]);
        assert_eq!(validator.voting_power, 100);
        assert_eq!(validator.proposer_priority, 0);
    }

    #[test]
    fn test_validator_set_creation() {
        let validators = create_test_validators();
        let set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        assert_eq!(set.validators.len(), 4);
        assert_eq!(set.total_voting_power, 40);
    }

    #[test]
    fn test_empty_validator_set() {
        let result = ValidatorSet::new(vec![], Height::new(1).expect("valid height"));
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_voting_power() {
        let validators = vec![Validator::new(vec![1], vec![1; 32], 0)];
        let result = ValidatorSet::new(validators, Height::new(1).expect("valid height"));
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_calculation() {
        let validators = create_test_validators();
        let set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        // Total power = 40, f = 13, quorum = 27
        assert_eq!(set.quorum(), 27);
    }

    #[test]
    fn test_proposer_selection() {
        let validators = vec![
            Validator::with_priority(vec![1], vec![1; 32], 10, 0),
            Validator::with_priority(vec![2], vec![2; 32], 20, 5),
            Validator::with_priority(vec![3], vec![3; 32], 10, 3),
        ];

        let mut set = ValidatorSet::new(validators.clone(), Height::new(1).expect("valid height"))
            .expect("valid validator set");
        set.validators = validators;

        // Validator 2 has highest priority (5)
        assert_eq!(set.proposer().address, vec![2]);
    }

    #[test]
    fn test_proposer_priority_rotation() {
        let validators = vec![
            Validator::new(vec![1], vec![1; 32], 10),
            Validator::new(vec![2], vec![2; 32], 20),
            Validator::new(vec![3], vec![3; 32], 10),
        ];

        let mut set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        // Initial: all priorities are 0, validator 1 is proposer (first in list)
        let proposer1 = set.proposer().address.clone();

        // After increment
        set.increment_proposer_priority();

        // Validator 2 should have higher priority due to more voting power
        let proposer2 = set.proposer().address.clone();

        // Priorities should have changed
        assert_ne!(proposer1, proposer2);
    }

    #[test]
    fn test_contains_validator() {
        let validators = create_test_validators();
        let set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        assert!(set.contains(&[1]));
        assert!(set.contains(&[2]));
        assert!(!set.contains(&[99]));
    }

    #[test]
    fn test_get_validator() {
        let validators = create_test_validators();
        let set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        let validator = set.get_validator(&[2]).expect("validator exists");
        assert_eq!(validator.address, vec![2]);
        assert_eq!(validator.voting_power, 10);

        assert!(set.get_validator(&[99]).is_none());
    }

    #[test]
    fn test_voting_power_calculation() {
        let validators = create_test_validators();
        let set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        let addresses = vec![vec![1], vec![2]];
        assert_eq!(set.voting_power_of(&addresses), 20);
    }

    #[test]
    fn test_has_quorum() {
        let validators = create_test_validators();
        let set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        // Need 27 out of 40, so need 3 validators (30 power)
        let quorum_addresses = vec![vec![1], vec![2], vec![3]];
        assert!(set.has_quorum(&quorum_addresses));

        // 2 validators (20 power) is not enough
        let no_quorum_addresses = vec![vec![1], vec![2]];
        assert!(!set.has_quorum(&no_quorum_addresses));
    }

    #[test]
    fn test_reset_proposer_priorities() {
        let validators = vec![
            Validator::with_priority(vec![1], vec![1; 32], 10, 100),
            Validator::with_priority(vec![2], vec![2; 32], 20, 200),
        ];

        let mut set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        set.reset_proposer_priorities();

        for validator in &set.validators {
            assert_eq!(validator.proposer_priority, 0);
        }
    }
}
