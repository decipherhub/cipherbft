use std::sync::Arc;

use informalsystems_malachitebft_core_types::{
    Context as MalachiteContext, NilOrVal, Round, ValueId, VoteType,
};

use crate::config::ConsensusConfig;
use crate::error::ConsensusError;
use crate::proposal::{CutProposal, CutProposalPart};
use crate::proposer_selector::ProposerSelector;
use crate::signing::Ed25519SigningScheme;
use crate::types::{ConsensusHeight, ConsensusValue};
use crate::validator_set::{ConsensusAddress, ConsensusValidator, ConsensusValidatorSet};
use crate::vote::ConsensusVote;

/// Extension payload for votes (empty for now).
pub type CipherBftContextExtension = Vec<u8>;

/// Aliases to make trait impl signatures clearer.
pub type CipherBftContextAddress = ConsensusAddress;
pub type CipherBftContextValidator = ConsensusValidator;
pub type CipherBftContextValidatorSet = ConsensusValidatorSet;
pub type CipherBftContextProposal = CutProposal;
pub type CipherBftContextProposalPart = CutProposalPart;
pub type CipherBftContextValue = ConsensusValue;
pub type CipherBftContextVote = ConsensusVote;
pub type CipherBftContextSigningScheme = Ed25519SigningScheme;

/// Malachite context implementation scaffold.
#[derive(Clone, Debug)]
pub struct CipherBftContext {
    /// Static consensus configuration.
    pub config: ConsensusConfig,
    /// Deterministic validator set for proposer selection and voting power.
    pub validator_set: ConsensusValidatorSet,
    /// Height the engine should start from.
    pub initial_height: ConsensusHeight,
    /// Proposer selector using Tendermint's weighted round-robin algorithm.
    proposer_selector: Arc<ProposerSelector>,
}

impl CipherBftContext {
    /// Create a new context with validation.
    ///
    /// # Errors
    /// Returns `ConsensusError::EmptyValidatorSet` if the validator set is empty.
    pub fn try_new(
        config: ConsensusConfig,
        validator_set: ConsensusValidatorSet,
        initial_height: ConsensusHeight,
    ) -> Result<Self, ConsensusError> {
        if validator_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }
        let proposer_selector = Arc::new(ProposerSelector::new(&validator_set, initial_height));
        Ok(Self {
            config,
            validator_set,
            initial_height,
            proposer_selector,
        })
    }

    /// Create a new context.
    ///
    /// # Panics
    /// Panics if the validator set is empty. Use `try_new` for fallible construction.
    pub fn new(
        config: ConsensusConfig,
        validator_set: ConsensusValidatorSet,
        initial_height: ConsensusHeight,
    ) -> Self {
        Self::try_new(config, validator_set, initial_height)
            .expect("validator set must not be empty")
    }

    /// Access the initial height.
    pub fn initial_height(&self) -> ConsensusHeight {
        self.initial_height
    }

    /// Access the validator set.
    pub fn validator_set(&self) -> &ConsensusValidatorSet {
        &self.validator_set
    }

    /// Chain ID accessor.
    pub fn chain_id(&self) -> &str {
        self.config.chain_id()
    }

    /// Access the proposer selector for external priority updates.
    pub fn proposer_selector(&self) -> &Arc<ProposerSelector> {
        &self.proposer_selector
    }

    /// Weighted round-robin proposer selection for a given height and round.
    pub fn proposer_at_round(
        &self,
        height: ConsensusHeight,
        round: Round,
    ) -> Option<ConsensusAddress> {
        if self.validator_set.is_empty() {
            return None;
        }
        let proposer = self
            .proposer_selector
            .select_proposer(&self.validator_set, height, round);
        Some(proposer.address)
    }
}

impl MalachiteContext for CipherBftContext {
    type Address = ConsensusAddress;
    type Height = ConsensusHeight;
    type ProposalPart = CutProposalPart;
    type Proposal = CutProposal;
    type Validator = ConsensusValidator;
    type ValidatorSet = ConsensusValidatorSet;
    type Value = ConsensusValue;
    type Vote = ConsensusVote;
    type Extension = CipherBftContextExtension;
    type SigningScheme = Ed25519SigningScheme;

    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        self.proposer_selector
            .select_proposer(validator_set, height, round)
    }

    fn new_proposal(
        &self,
        height: Self::Height,
        round: Round,
        value: Self::Value,
        pol_round: Round,
        address: Self::Address,
    ) -> Self::Proposal {
        CutProposal::new(height, round, value, pol_round, address)
    }

    fn new_prevote(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        // Note: CONSENSUS_PREVOTES_RECEIVED should track votes received from network,
        // not vote creation. Vote receipt tracking belongs in the gossip/network layer.
        ConsensusVote::new(height, round, value_id, VoteType::Prevote, address)
    }

    fn new_precommit(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        // Note: CONSENSUS_PRECOMMITS_RECEIVED should track votes received from network,
        // not vote creation. Vote receipt tracking belongs in the gossip/network layer.
        ConsensusVote::new(height, round, value_id, VoteType::Precommit, address)
    }
}
