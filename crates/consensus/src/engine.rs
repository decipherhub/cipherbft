//! Consensus engine orchestration for Autobahn BFT.
//!
//! Coordinates the two-layer consensus protocol:
//! - Layer 1: Car creation (data dissemination)
//! - Layer 2: Cut consensus (PBFT-style voting)

use crate::car::{Car, CarBuilder};
use crate::proposal::{Cut, CutBuilder};
use crate::state_machine::{ConsensusState, ConsensusStep};
use crate::vote_set::VoteSet;
use std::collections::HashMap;
use tokio::sync::mpsc;
use types::{Block, Hash, Height, Round, ValidatorSet, Vote, VoteType};

/// Events processed by the consensus engine.
#[derive(Debug, Clone)]
pub enum ConsensusEvent {
    /// Start consensus at a new height.
    NewHeight(Height),
    /// Timeout for propose step.
    ProposeTimeout,
    /// Timeout for prepare step.
    PrepareTimeout,
    /// Timeout for commit step.
    CommitTimeout,
    /// Received a proposal.
    Proposal(Cut),
    /// Received a vote.
    Vote(Vote),
    /// Request to create a Car (Layer 1).
    CreateCar(Vec<Vec<u8>>),
}

/// Configuration for the consensus engine.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Our validator address.
    pub validator_address: Vec<u8>,
    /// Initial validator set.
    pub validator_set: ValidatorSet,
    /// Maximum transactions per Car.
    pub max_car_txs: usize,
    /// Maximum Car size in bytes.
    pub max_car_size: usize,
    /// Maximum validators (Cars) per Cut.
    pub max_cars_per_cut: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            validator_address: vec![],
            validator_set: ValidatorSet::new(vec![], Height::new(1).unwrap_or_else(|_| panic!("invalid height")))
                .unwrap_or_else(|_| panic!("invalid validator set")),
            max_car_txs: 1000,
            max_car_size: 1024 * 1024, // 1 MB
            max_cars_per_cut: 100,
        }
    }
}

/// Consensus engine coordinating Autobahn BFT.
pub struct ConsensusEngine {
    /// Configuration.
    config: ConsensusConfig,
    /// Current consensus state.
    state: ConsensusState,
    /// Prepare vote sets by height/round.
    prepare_votes: HashMap<(Height, Round), VoteSet>,
    /// Commit vote sets by height/round.
    commit_votes: HashMap<(Height, Round), VoteSet>,
    /// Cars pending inclusion in next Cut (by validator).
    pending_cars: HashMap<Vec<u8>, Car>,
    /// Event receiver.
    event_rx: mpsc::UnboundedReceiver<ConsensusEvent>,
    /// Event sender (for internal events).
    event_tx: mpsc::UnboundedSender<ConsensusEvent>,
}

impl ConsensusEngine {
    /// Create a new consensus engine.
    pub fn new(config: ConsensusConfig, initial_height: Height) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let state = ConsensusState::new(initial_height, config.validator_set.clone());

        Self {
            config,
            state,
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            pending_cars: HashMap::new(),
            event_rx,
            event_tx,
        }
    }

    /// Get event sender for external events.
    pub fn event_sender(&self) -> mpsc::UnboundedSender<ConsensusEvent> {
        self.event_tx.clone()
    }

    /// Run the consensus engine event loop.
    pub async fn run(&mut self) {
        while let Some(event) = self.event_rx.recv().await {
            self.handle_event(event).await;
        }
    }

    /// Handle a consensus event.
    async fn handle_event(&mut self, event: ConsensusEvent) {
        match event {
            ConsensusEvent::NewHeight(height) => {
                self.handle_new_height(height).await;
            }
            ConsensusEvent::ProposeTimeout => {
                self.handle_propose_timeout().await;
            }
            ConsensusEvent::PrepareTimeout => {
                self.handle_prepare_timeout().await;
            }
            ConsensusEvent::CommitTimeout => {
                self.handle_commit_timeout().await;
            }
            ConsensusEvent::Proposal(cut) => {
                self.handle_proposal(cut).await;
            }
            ConsensusEvent::Vote(vote) => {
                self.handle_vote(vote).await;
            }
            ConsensusEvent::CreateCar(transactions) => {
                self.handle_create_car(transactions).await;
            }
        }
    }

    /// Handle new height event.
    async fn handle_new_height(&mut self, height: Height) {
        if height > self.state.height {
            self.state.advance_height(height, self.config.validator_set.clone());
            self.prepare_votes.clear();
            self.commit_votes.clear();
            self.pending_cars.clear();
        }

        // Enter propose step
        self.state.enter_propose();

        // If we're the proposer, create a proposal
        if self.state.is_proposer(&self.config.validator_address) {
            self.create_proposal().await;
        }
    }

    /// Handle propose timeout.
    async fn handle_propose_timeout(&mut self) {
        // Move to next round if no proposal received
        if self.state.step == ConsensusStep::Propose && self.state.proposal.is_none() {
            let next_round = Round::new(self.state.round.value() + 1);
            self.state.enter_new_round(next_round);
            self.state.enter_propose();

            // Check if we're proposer in new round
            if self.state.is_proposer(&self.config.validator_address) {
                self.create_proposal().await;
            }
        }
    }

    /// Handle prepare timeout.
    async fn handle_prepare_timeout(&mut self) {
        // Move to next round if no prepare quorum
        if self.state.step == ConsensusStep::Prepare {
            let next_round = Round::new(self.state.round.value() + 1);
            self.state.enter_new_round(next_round);
            self.state.enter_propose();

            if self.state.is_proposer(&self.config.validator_address) {
                self.create_proposal().await;
            }
        }
    }

    /// Handle commit timeout.
    async fn handle_commit_timeout(&mut self) {
        // Move to next round if no commit quorum
        if self.state.step == ConsensusStep::Commit {
            let next_round = Round::new(self.state.round.value() + 1);
            self.state.enter_new_round(next_round);
            self.state.enter_propose();

            if self.state.is_proposer(&self.config.validator_address) {
                self.create_proposal().await;
            }
        }
    }

    /// Handle proposal reception.
    async fn handle_proposal(&mut self, cut: Cut) {
        // Validate proposal
        if !self.validate_proposal(&cut) {
            return;
        }

        // Convert Cut to Block
        let previous_hash = self.get_previous_hash();
        let app_hash = Hash::new([0; 32]); // TODO: Get from ABCI

        let block = cut.to_block(
            self.state.height,
            self.state.proposer().address.clone(),
            previous_hash,
            app_hash,
        );

        // Enter prepare step with proposal
        self.state.enter_prepare(block.clone());

        // Vote prepare
        let prepare_vote = self.create_vote(VoteType::Prepare, block.hash());
        self.handle_vote(prepare_vote).await;
    }

    /// Handle vote reception.
    async fn handle_vote(&mut self, vote: Vote) {
        let key = (vote.height, vote.round);
        let mut should_send_commit = None;
        let mut should_finalize = None;

        match vote.vote_type {
            VoteType::Prepare => {
                // Get or create vote set
                let vote_set = self.prepare_votes.entry(key).or_insert_with(|| {
                    VoteSet::new(
                        vote.height,
                        vote.round,
                        VoteType::Prepare,
                        self.config.validator_set.clone(),
                    )
                });

                // Add vote
                if vote_set.add_vote(vote.clone()) {
                    // Check for quorum
                    if let Some(block_hash) = vote_set.has_any_quorum() {
                        if self.state.step == ConsensusStep::Prepare {
                            // Enter commit step
                            self.state.enter_commit(block_hash);

                            // Schedule commit vote
                            should_send_commit = Some(block_hash);
                        }
                    }
                }
            }
            VoteType::Commit => {
                // Get or create vote set
                let vote_set = self.commit_votes.entry(key).or_insert_with(|| {
                    VoteSet::new(
                        vote.height,
                        vote.round,
                        VoteType::Commit,
                        self.config.validator_set.clone(),
                    )
                });

                // Add vote
                if vote_set.add_vote(vote.clone()) {
                    // Check for quorum
                    if let Some(block_hash) = vote_set.has_any_quorum() {
                        if self.state.step == ConsensusStep::Commit {
                            if let Some(block) = &self.state.proposal {
                                if block.hash() == block_hash {
                                    // Schedule finalization
                                    should_finalize = Some(block.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Handle scheduled actions (after mutable borrow is released)
        if let Some(block_hash) = should_send_commit {
            let commit_vote = self.create_vote(VoteType::Commit, block_hash);
            // Send commit vote as new event
            let _ = self.event_tx.send(ConsensusEvent::Vote(commit_vote));
        }

        if let Some(block) = should_finalize {
            self.finalize_block(block).await;
        }
    }

    /// Handle Car creation request.
    async fn handle_create_car(&mut self, transactions: Vec<Vec<u8>>) {
        let car_id = self.validator_to_car_id(&self.config.validator_address);
        let sequence = self.get_next_car_sequence(car_id);
        let previous_hash = self.get_previous_car_hash(car_id);

        let mut builder = CarBuilder::new(car_id, sequence, previous_hash)
            .with_max_tx_count(self.config.max_car_txs)
            .with_max_size(self.config.max_car_size);

        for tx in transactions {
            builder.add_transaction(tx);
        }

        let car = builder.build(chrono::Utc::now());

        // Store car for inclusion in next Cut
        self.pending_cars.insert(self.config.validator_address.clone(), car);
    }

    /// Create a proposal (Cut).
    async fn create_proposal(&mut self) {
        let cut_id = self.state.height.value();
        let mut builder = CutBuilder::new(cut_id, self.state.round)
            .with_max_cars(self.config.max_cars_per_cut);

        // Add all pending cars
        for car in self.pending_cars.values() {
            builder.add_car(car.clone());
        }

        let cut = builder.build(chrono::Utc::now());

        // Handle our own proposal
        self.handle_proposal(cut).await;
    }

    /// Validate a proposal.
    fn validate_proposal(&self, cut: &Cut) -> bool {
        // Verify Cut hash
        if !cut.verify_hash() {
            return false;
        }

        // Verify all Cars
        if !cut.verify_cars() {
            return false;
        }

        // Verify round matches
        if cut.metadata.round != self.state.round {
            return false;
        }

        true
    }

    /// Create a vote.
    fn create_vote(&self, vote_type: VoteType, block_hash: Hash) -> Vote {
        Vote::new(
            vote_type,
            self.state.height,
            self.state.round,
            block_hash,
            self.config.validator_address.clone(),
            vec![0; 64], // TODO: Sign with private key
            chrono::Utc::now(),
        )
    }

    /// Finalize a block.
    async fn finalize_block(&mut self, block: Block) {
        self.state.finalize(block.clone());

        // Move to next height
        let next_height = Height::new(self.state.height.value() + 1)
            .unwrap_or_else(|_| panic!("invalid height"));

        // Send new height event
        let _ = self.event_tx.send(ConsensusEvent::NewHeight(next_height));
    }

    /// Get previous block hash.
    fn get_previous_hash(&self) -> Hash {
        if let Some(block) = &self.state.last_commit {
            block.hash()
        } else {
            Hash::new([0; 32]) // Genesis
        }
    }

    /// Convert validator address to car ID.
    fn validator_to_car_id(&self, address: &[u8]) -> u64 {
        // Simple hash-based mapping
        let mut sum: u64 = 0;
        for (i, &byte) in address.iter().enumerate().take(8) {
            sum |= (byte as u64) << (i * 8);
        }
        sum
    }

    /// Get next car sequence for a validator.
    fn get_next_car_sequence(&self, _car_id: u64) -> u64 {
        // TODO: Track car sequences properly
        0
    }

    /// Get previous car hash for a validator.
    fn get_previous_car_hash(&self, _car_id: u64) -> Hash {
        // TODO: Track car chains properly
        Hash::new([0; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Validator;

    fn create_test_config() -> ConsensusConfig {
        let validators = vec![
            Validator::new(vec![1], vec![1; 32], 10),
            Validator::new(vec![2], vec![2; 32], 10),
            Validator::new(vec![3], vec![3; 32], 10),
            Validator::new(vec![4], vec![4; 32], 10),
        ];

        let validator_set = ValidatorSet::new(validators, Height::new(1).expect("valid height"))
            .expect("valid validator set");

        ConsensusConfig {
            validator_address: vec![1],
            validator_set,
            max_car_txs: 100,
            max_car_size: 10240,
            max_cars_per_cut: 4,
        }
    }

    #[test]
    fn test_engine_creation() {
        let config = create_test_config();
        let engine = ConsensusEngine::new(config, Height::new(1).expect("valid height"));

        assert_eq!(engine.state.height, Height::new(1).expect("valid height"));
        assert_eq!(engine.state.step, ConsensusStep::NewHeight);
    }

    #[test]
    fn test_event_sender() {
        let config = create_test_config();
        let engine = ConsensusEngine::new(config, Height::new(1).expect("valid height"));

        let sender = engine.event_sender();
        assert!(sender.send(ConsensusEvent::ProposeTimeout).is_ok());
    }

    #[tokio::test]
    async fn test_new_height_event() {
        let config = create_test_config();
        let mut engine = ConsensusEngine::new(config, Height::new(1).expect("valid height"));

        engine.handle_new_height(Height::new(2).expect("valid height")).await;

        assert_eq!(engine.state.height, Height::new(2).expect("valid height"));
        assert_eq!(engine.state.step, ConsensusStep::Propose);
    }

    #[tokio::test]
    async fn test_car_creation() {
        let config = create_test_config();
        let mut engine = ConsensusEngine::new(config, Height::new(1).expect("valid height"));

        let transactions = vec![vec![1, 2, 3], vec![4, 5, 6]];
        engine.handle_create_car(transactions).await;

        assert_eq!(engine.pending_cars.len(), 1);
        let car = engine.pending_cars.get(&vec![1]).expect("car exists");
        assert_eq!(car.tx_count(), 2);
    }

    #[test]
    fn test_proposal_validation() {
        let config = create_test_config();
        let engine = ConsensusEngine::new(config, Height::new(1).expect("valid height"));

        let cut = Cut::new(1, Round::new(0), vec![], chrono::Utc::now());

        assert!(engine.validate_proposal(&cut));
    }
}
