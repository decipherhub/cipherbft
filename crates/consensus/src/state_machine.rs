//! Consensus state machine for Autobahn BFT.
//!
//! Implements the state transitions for the two-layer Autobahn consensus:
//! - Layer 1: Car creation (data dissemination)
//! - Layer 2: Cut consensus (PBFT-style voting)

use serde::{Deserialize, Serialize};
use std::fmt;
use types::{Block, Hash, Height, Round, ValidatorSet, Vote, VoteType};

/// Consensus step in the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusStep {
    /// New height: waiting for proposal.
    NewHeight,
    /// Propose: leader creates proposal.
    Propose,
    /// Prepare: validators vote on proposal.
    Prepare,
    /// Commit: validators commit to proposal.
    Commit,
    /// Finalized: block committed and executed.
    Finalized,
}

impl fmt::Display for ConsensusStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusStep::NewHeight => write!(f, "NewHeight"),
            ConsensusStep::Propose => write!(f, "Propose"),
            ConsensusStep::Prepare => write!(f, "Prepare"),
            ConsensusStep::Commit => write!(f, "Commit"),
            ConsensusStep::Finalized => write!(f, "Finalized"),
        }
    }
}

/// Consensus state for a specific height and round.
#[derive(Debug, Clone)]
pub struct ConsensusState {
    /// Current blockchain height.
    pub height: Height,
    /// Current consensus round.
    pub round: Round,
    /// Current consensus step.
    pub step: ConsensusStep,
    /// Validator set for this height.
    pub validators: ValidatorSet,
    /// Proposed block (if any).
    pub proposal: Option<Block>,
    /// Hash of the locked block (from Prepare phase).
    pub locked_block: Option<Hash>,
    /// Round when we locked on a block.
    pub locked_round: Option<Round>,
    /// Hash of block we're valid for (from Commit phase).
    pub valid_block: Option<Hash>,
    /// Round when we saw valid block.
    pub valid_round: Option<Round>,
    /// Prepare votes received.
    pub prepare_votes: Vec<Vote>,
    /// Commit votes received.
    pub commit_votes: Vec<Vote>,
    /// Last committed block.
    pub last_commit: Option<Block>,
}

impl ConsensusState {
    /// Create a new consensus state for a given height.
    pub fn new(height: Height, validators: ValidatorSet) -> Self {
        Self {
            height,
            round: Round::default(),
            step: ConsensusStep::NewHeight,
            validators,
            proposal: None,
            locked_block: None,
            locked_round: None,
            valid_block: None,
            valid_round: None,
            prepare_votes: Vec::new(),
            commit_votes: Vec::new(),
            last_commit: None,
        }
    }

    /// Transition to a new round.
    pub fn enter_new_round(&mut self, round: Round) {
        self.round = round;
        self.step = ConsensusStep::NewHeight;
        self.proposal = None;
        self.prepare_votes.clear();
        self.commit_votes.clear();
    }

    /// Transition to Propose step.
    pub fn enter_propose(&mut self) {
        self.step = ConsensusStep::Propose;
    }

    /// Transition to Prepare step with a proposal.
    pub fn enter_prepare(&mut self, proposal: Block) {
        self.proposal = Some(proposal);
        self.step = ConsensusStep::Prepare;
    }

    /// Transition to Commit step.
    pub fn enter_commit(&mut self, block_hash: Hash) {
        self.locked_block = Some(block_hash);
        self.locked_round = Some(self.round);
        self.step = ConsensusStep::Commit;
    }

    /// Finalize the current height.
    pub fn finalize(&mut self, block: Block) {
        self.last_commit = Some(block);
        self.step = ConsensusStep::Finalized;
    }

    /// Add a prepare vote.
    pub fn add_prepare_vote(&mut self, vote: Vote) {
        if vote.vote_type == VoteType::Prepare && vote.height == self.height && vote.round == self.round {
            self.prepare_votes.push(vote);
        }
    }

    /// Add a commit vote.
    pub fn add_commit_vote(&mut self, vote: Vote) {
        if vote.vote_type == VoteType::Commit && vote.height == self.height && vote.round == self.round {
            self.commit_votes.push(vote);
        }
    }

    /// Check if we have 2f+1 prepare votes for a specific block.
    pub fn has_prepare_quorum(&self, block_hash: &Hash) -> bool {
        let votes_for_block: Vec<_> = self
            .prepare_votes
            .iter()
            .filter(|v| &v.block_hash == block_hash)
            .collect();

        let addresses: Vec<_> = votes_for_block
            .iter()
            .map(|v| v.validator_address.clone())
            .collect();

        self.validators.has_quorum(&addresses)
    }

    /// Check if we have 2f+1 commit votes for a specific block.
    pub fn has_commit_quorum(&self, block_hash: &Hash) -> bool {
        let votes_for_block: Vec<_> = self
            .commit_votes
            .iter()
            .filter(|v| &v.block_hash == block_hash)
            .collect();

        let addresses: Vec<_> = votes_for_block
            .iter()
            .map(|v| v.validator_address.clone())
            .collect();

        self.validators.has_quorum(&addresses)
    }

    /// Get the current proposer for this round.
    pub fn proposer(&self) -> &types::Validator {
        self.validators.proposer()
    }

    /// Check if we are the proposer for this round.
    pub fn is_proposer(&self, address: &[u8]) -> bool {
        self.proposer().address == address
    }

    /// Reset state for new height.
    pub fn advance_height(&mut self, new_height: Height, new_validators: ValidatorSet) {
        self.height = new_height;
        self.round = Round::default();
        self.step = ConsensusStep::NewHeight;
        self.validators = new_validators;
        self.proposal = None;
        self.locked_block = None;
        self.locked_round = None;
        self.valid_block = None;
        self.valid_round = None;
        self.prepare_votes.clear();
        self.commit_votes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_consensus_state_creation() {
        let validators = create_test_validators();
        let state = ConsensusState::new(Height::new(1).expect("valid height"), validators);

        assert_eq!(state.height, Height::new(1).expect("valid height"));
        assert_eq!(state.round, Round::default());
        assert_eq!(state.step, ConsensusStep::NewHeight);
    }

    #[test]
    fn test_step_transitions() {
        let validators = create_test_validators();
        let mut state = ConsensusState::new(Height::new(1).expect("valid height"), validators);

        state.enter_propose();
        assert_eq!(state.step, ConsensusStep::Propose);

        let block = Block::new(
            types::BlockHeader::new(
                Height::new(1).expect("valid height"),
                Hash::new([1; 32]),
                Round::new(0),
                chrono::Utc::now(),
                vec![1],
                Hash::new([0; 32]),
                Hash::new([2; 32]),
                Hash::new([3; 32]),
            ),
            types::BlockData::new(vec![]),
            None,
            None,
            vec![],
        );

        state.enter_prepare(block.clone());
        assert_eq!(state.step, ConsensusStep::Prepare);
        assert!(state.proposal.is_some());

        state.enter_commit(block.hash());
        assert_eq!(state.step, ConsensusStep::Commit);
        assert!(state.locked_block.is_some());
    }

    #[test]
    fn test_round_advancement() {
        let validators = create_test_validators();
        let mut state = ConsensusState::new(Height::new(1).expect("valid height"), validators);

        state.enter_new_round(Round::new(1));
        assert_eq!(state.round, Round::new(1));
        assert_eq!(state.step, ConsensusStep::NewHeight);
        assert!(state.proposal.is_none());
    }

    #[test]
    fn test_height_advancement() {
        let validators = create_test_validators();
        let mut state = ConsensusState::new(Height::new(1).expect("valid height"), validators.clone());

        state.advance_height(Height::new(2).expect("valid height"), validators);
        assert_eq!(state.height, Height::new(2).expect("valid height"));
        assert_eq!(state.round, Round::default());
        assert_eq!(state.step, ConsensusStep::NewHeight);
    }

    #[test]
    fn test_proposer_check() {
        let validators = create_test_validators();
        let state = ConsensusState::new(Height::new(1).expect("valid height"), validators);

        let proposer = state.proposer();
        assert!(state.is_proposer(&proposer.address));
        assert!(!state.is_proposer(&[99]));
    }
}
