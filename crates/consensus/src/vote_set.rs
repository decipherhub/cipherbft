//! Vote set tracking and aggregation.
//!
//! Tracks votes received for a specific height and round,
//! detecting when quorum is reached for consensus.

use std::collections::HashMap;
use types::{Hash, Height, Round, ValidatorSet, Vote, VoteType};

/// Vote set for tracking votes at a specific height/round.
#[derive(Debug, Clone)]
pub struct VoteSet {
    /// Height these votes are for.
    pub height: Height,
    /// Round these votes are for.
    pub round: Round,
    /// Type of votes (Prepare or Commit).
    pub vote_type: VoteType,
    /// Validator set for vote validation.
    pub validators: ValidatorSet,
    /// Votes by validator address.
    votes: HashMap<Vec<u8>, Vote>,
    /// Votes grouped by block hash.
    votes_by_block: HashMap<Hash, Vec<Vec<u8>>>,
}

impl VoteSet {
    /// Create a new vote set.
    pub fn new(height: Height, round: Round, vote_type: VoteType, validators: ValidatorSet) -> Self {
        Self {
            height,
            round,
            vote_type,
            validators,
            votes: HashMap::new(),
            votes_by_block: HashMap::new(),
        }
    }

    /// Add a vote to the set.
    ///
    /// Returns true if the vote was added, false if duplicate or invalid.
    pub fn add_vote(&mut self, vote: Vote) -> bool {
        // Validate vote matches our height/round/type
        if vote.height != self.height
            || vote.round != self.round
            || vote.vote_type != self.vote_type
        {
            return false;
        }

        // Check if validator is in the set
        if !self.validators.contains(&vote.validator_address) {
            return false;
        }

        // Check for duplicate
        if self.votes.contains_key(&vote.validator_address) {
            return false;
        }

        // Add to votes by block
        self.votes_by_block
            .entry(vote.block_hash)
            .or_default()
            .push(vote.validator_address.clone());

        // Add to main votes map
        self.votes
            .insert(vote.validator_address.clone(), vote);

        true
    }

    /// Check if we have quorum (2f+1) for any block.
    pub fn has_any_quorum(&self) -> Option<Hash> {
        for (block_hash, addresses) in &self.votes_by_block {
            if self.validators.has_quorum(addresses) {
                return Some(*block_hash);
            }
        }
        None
    }

    /// Check if we have quorum for a specific block.
    pub fn has_quorum_for(&self, block_hash: &Hash) -> bool {
        if let Some(addresses) = self.votes_by_block.get(block_hash) {
            self.validators.has_quorum(addresses)
        } else {
            false
        }
    }

    /// Get total voting power received.
    pub fn total_voting_power(&self) -> u64 {
        let addresses: Vec<_> = self.votes.keys().cloned().collect();
        self.validators.voting_power_of(&addresses)
    }

    /// Get voting power for a specific block.
    pub fn voting_power_for(&self, block_hash: &Hash) -> u64 {
        if let Some(addresses) = self.votes_by_block.get(block_hash) {
            self.validators.voting_power_of(addresses)
        } else {
            0
        }
    }

    /// Get number of votes.
    pub fn len(&self) -> usize {
        self.votes.len()
    }

    /// Check if vote set is empty.
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    /// Get all votes.
    pub fn votes(&self) -> impl Iterator<Item = &Vote> {
        self.votes.values()
    }

    /// Get votes for a specific block.
    pub fn votes_for_block(&self, block_hash: &Hash) -> Vec<&Vote> {
        if let Some(addresses) = self.votes_by_block.get(block_hash) {
            addresses
                .iter()
                .filter_map(|addr| self.votes.get(addr))
                .collect()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use types::Validator;

    fn create_test_validators() -> ValidatorSet {
        let validators = vec![
            Validator::new(vec![1], vec![1; 32], 10),
            Validator::new(vec![2], vec![2; 32], 10),
            Validator::new(vec![3], vec![3; 32], 10),
            Validator::new(vec![4], vec![4; 32], 10),
        ];

        ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set")
    }

    fn create_test_vote(
        validator_addr: Vec<u8>,
        block_hash: Hash,
        vote_type: VoteType,
    ) -> Vote {
        Vote::new(
            vote_type,
            Height::new(1).expect("valid height"),
            Round::new(0),
            block_hash,
            validator_addr,
            vec![0; 64],
            Utc::now(),
        )
    }

    #[test]
    fn test_vote_set_creation() {
        let validators = create_test_validators();
        let vote_set = VoteSet::new(
            Height::new(1).expect("valid height"),
            Round::new(0),
            VoteType::Prepare,
            validators,
        );

        assert_eq!(vote_set.height, Height::new(1).expect("valid height"));
        assert_eq!(vote_set.round, Round::new(0));
        assert_eq!(vote_set.vote_type, VoteType::Prepare);
        assert!(vote_set.is_empty());
    }

    #[test]
    fn test_add_vote() {
        let validators = create_test_validators();
        let mut vote_set = VoteSet::new(
            Height::new(1).expect("valid height"),
            Round::new(0),
            VoteType::Prepare,
            validators,
        );

        let block_hash = Hash::new([1; 32]);
        let vote = create_test_vote(vec![1], block_hash, VoteType::Prepare);

        assert!(vote_set.add_vote(vote.clone()));
        assert_eq!(vote_set.len(), 1);

        // Duplicate vote should be rejected
        assert!(!vote_set.add_vote(vote));
        assert_eq!(vote_set.len(), 1);
    }

    #[test]
    fn test_invalid_vote_rejection() {
        let validators = create_test_validators();
        let mut vote_set = VoteSet::new(
            Height::new(1).expect("valid height"),
            Round::new(0),
            VoteType::Prepare,
            validators,
        );

        let block_hash = Hash::new([1; 32]);

        // Wrong height
        let wrong_height = Vote::new(
            VoteType::Prepare,
            Height::new(2).expect("valid height"),
            Round::new(0),
            block_hash,
            vec![1],
            vec![0; 64],
            Utc::now(),
        );
        assert!(!vote_set.add_vote(wrong_height));

        // Wrong vote type
        let wrong_type = create_test_vote(vec![1], block_hash, VoteType::Commit);
        assert!(!vote_set.add_vote(wrong_type));

        // Unknown validator
        let unknown_validator = create_test_vote(vec![99], block_hash, VoteType::Prepare);
        assert!(!vote_set.add_vote(unknown_validator));
    }

    #[test]
    fn test_quorum_detection() {
        let validators = create_test_validators();
        let mut vote_set = VoteSet::new(
            Height::new(1).expect("valid height"),
            Round::new(0),
            VoteType::Prepare,
            validators,
        );

        let block_hash = Hash::new([1; 32]);

        // Add 3 votes for same block (need 27 power out of 40, which is 3 validators)
        vote_set.add_vote(create_test_vote(vec![1], block_hash, VoteType::Prepare));
        vote_set.add_vote(create_test_vote(vec![2], block_hash, VoteType::Prepare));

        // Not yet quorum
        assert!(!vote_set.has_quorum_for(&block_hash));
        assert!(vote_set.has_any_quorum().is_none());

        // Third vote reaches quorum
        vote_set.add_vote(create_test_vote(vec![3], block_hash, VoteType::Prepare));

        assert!(vote_set.has_quorum_for(&block_hash));
        assert_eq!(vote_set.has_any_quorum(), Some(block_hash));
    }

    #[test]
    fn test_voting_power_calculation() {
        let validators = create_test_validators();
        let mut vote_set = VoteSet::new(
            Height::new(1).expect("valid height"),
            Round::new(0),
            VoteType::Prepare,
            validators,
        );

        let block_hash = Hash::new([1; 32]);

        vote_set.add_vote(create_test_vote(vec![1], block_hash, VoteType::Prepare));
        vote_set.add_vote(create_test_vote(vec![2], block_hash, VoteType::Prepare));

        assert_eq!(vote_set.total_voting_power(), 20);
        assert_eq!(vote_set.voting_power_for(&block_hash), 20);
    }

    #[test]
    fn test_votes_for_multiple_blocks() {
        let validators = create_test_validators();
        let mut vote_set = VoteSet::new(
            Height::new(1).expect("valid height"),
            Round::new(0),
            VoteType::Prepare,
            validators,
        );

        let block1 = Hash::new([1; 32]);
        let block2 = Hash::new([2; 32]);

        vote_set.add_vote(create_test_vote(vec![1], block1, VoteType::Prepare));
        vote_set.add_vote(create_test_vote(vec![2], block1, VoteType::Prepare));
        vote_set.add_vote(create_test_vote(vec![3], block2, VoteType::Prepare));

        assert_eq!(vote_set.voting_power_for(&block1), 20);
        assert_eq!(vote_set.voting_power_for(&block2), 10);
        assert_eq!(vote_set.votes_for_block(&block1).len(), 2);
        assert_eq!(vote_set.votes_for_block(&block2).len(), 1);
    }
}
