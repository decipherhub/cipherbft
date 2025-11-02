//! Validator types.

use crate::Height;
use serde::{Deserialize, Serialize};

/// A validator in the consensus network.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Validator {
    /// Validator address.
    pub address: Vec<u8>,
    /// Public key.
    pub public_key: Vec<u8>,
    /// Voting power.
    pub voting_power: u64,
    /// Proposer priority for leader selection.
    pub proposer_priority: i64,
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
    /// Calculate quorum (2f+1).
    pub fn quorum(&self) -> u64 {
        let f = (self.total_voting_power - 1) / 3;
        2 * f + 1
    }

    /// Check if address is in validator set.
    pub fn contains(&self, address: &[u8]) -> bool {
        self.validators.iter().any(|v| v.address == address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_calculation() {
        let validators = vec![
            Validator {
                address: vec![1],
                public_key: vec![],
                voting_power: 10,
                proposer_priority: 0,
            },
            Validator {
                address: vec![2],
                public_key: vec![],
                voting_power: 10,
                proposer_priority: 0,
            },
            Validator {
                address: vec![3],
                public_key: vec![],
                voting_power: 10,
                proposer_priority: 0,
            },
            Validator {
                address: vec![4],
                public_key: vec![],
                voting_power: 10,
                proposer_priority: 0,
            },
        ];

        let set = ValidatorSet {
            validators,
            total_voting_power: 40,
            height: Height::new(1).unwrap(),
        };

        // For n=4 validators: f=1, quorum=3
        assert_eq!(set.quorum(), 27); // 2*13+1 = 27 (rounded)
    }
}
