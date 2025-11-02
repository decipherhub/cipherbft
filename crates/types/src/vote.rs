//! Vote types for consensus protocol.
//!
//! Votes are signed messages from validators expressing their support
//! for specific blocks during the Prepare and Commit phases of consensus.

use crate::{Hash, Height, Round};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of vote (Prepare or Commit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Prepare phase vote (first phase of two-phase commit).
    Prepare,
    /// Commit phase vote (second phase of two-phase commit).
    Commit,
}

impl VoteType {
    /// Get string representation of vote type.
    pub fn as_str(&self) -> &'static str {
        match self {
            VoteType::Prepare => "Prepare",
            VoteType::Commit => "Commit",
        }
    }
}

/// A vote from a validator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vote {
    /// Vote type.
    pub vote_type: VoteType,
    /// Block height.
    pub height: Height,
    /// Consensus round.
    pub round: Round,
    /// Block hash being voted for.
    pub block_hash: Hash,
    /// Validator address.
    pub validator_address: Vec<u8>,
    /// Vote signature.
    pub signature: Vec<u8>,
    /// Vote timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Vote {
    /// Create a new vote.
    pub fn new(
        vote_type: VoteType,
        height: Height,
        round: Round,
        block_hash: Hash,
        validator_address: Vec<u8>,
        signature: Vec<u8>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            vote_type,
            height,
            round,
            block_hash,
            validator_address,
            signature,
            timestamp,
        }
    }

    /// Get the canonical bytes to sign for this vote.
    ///
    /// This creates a deterministic byte representation used for signature
    /// generation and verification.
    pub fn sign_bytes(&self) -> Vec<u8> {
        // Canonical encoding: type(1) + height(8) + round(4) + hash(32)
        let mut bytes = Vec::with_capacity(45);

        // Vote type as single byte
        bytes.push(match self.vote_type {
            VoteType::Prepare => 0x01,
            VoteType::Commit => 0x02,
        });

        // Height as 8 bytes (big-endian)
        bytes.extend_from_slice(&self.height.value().to_be_bytes());

        // Round as 4 bytes (big-endian)
        bytes.extend_from_slice(&self.round.value().to_be_bytes());

        // Block hash
        bytes.extend_from_slice(self.block_hash.as_bytes());

        bytes
    }

    /// Check if this vote is for the same block and type as another vote.
    pub fn matches(&self, other: &Vote) -> bool {
        self.vote_type == other.vote_type
            && self.height == other.height
            && self.round == other.round
            && self.block_hash == other.block_hash
    }

    /// Check if this is a Prepare vote.
    pub fn is_prepare(&self) -> bool {
        self.vote_type == VoteType::Prepare
    }

    /// Check if this is a Commit vote.
    pub fn is_commit(&self) -> bool {
        self.vote_type == VoteType::Commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vote(vote_type: VoteType) -> Vote {
        Vote::new(
            vote_type,
            Height::new(1).expect("valid height"),
            Round::new(0),
            Hash::new([1; 32]),
            vec![1, 2, 3],
            vec![0; 64],
            Utc::now(),
        )
    }

    #[test]
    fn test_vote_creation() {
        let vote = create_test_vote(VoteType::Prepare);
        assert!(vote.is_prepare());
        assert!(!vote.is_commit());
        assert_eq!(vote.vote_type.as_str(), "Prepare");
    }

    #[test]
    fn test_vote_type_string() {
        assert_eq!(VoteType::Prepare.as_str(), "Prepare");
        assert_eq!(VoteType::Commit.as_str(), "Commit");
    }

    #[test]
    fn test_vote_matches() {
        let vote1 = create_test_vote(VoteType::Prepare);
        let vote2 = Vote::new(
            VoteType::Prepare,
            vote1.height,
            vote1.round,
            vote1.block_hash,
            vec![4, 5, 6], // Different validator
            vec![0; 64],
            Utc::now(),
        );

        // Should match despite different validator
        assert!(vote1.matches(&vote2));

        // Different vote type should not match
        let vote3 = create_test_vote(VoteType::Commit);
        assert!(!vote1.matches(&vote3));
    }

    #[test]
    fn test_sign_bytes_deterministic() {
        let vote = create_test_vote(VoteType::Prepare);
        let bytes1 = vote.sign_bytes();
        let bytes2 = vote.sign_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 45); // 1 + 8 + 4 + 32
    }

    #[test]
    fn test_sign_bytes_different_for_different_types() {
        let prepare = create_test_vote(VoteType::Prepare);
        let commit = Vote::new(
            VoteType::Commit,
            prepare.height,
            prepare.round,
            prepare.block_hash,
            prepare.validator_address.clone(),
            vec![],
            Utc::now(),
        );

        assert_ne!(prepare.sign_bytes(), commit.sign_bytes());
    }
}
