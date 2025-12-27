use informalsystems_malachitebft_core_types::{
    Context as MalachiteContext, NilOrVal, Round, ValueId, VoteType,
};

use crate::config::ConsensusConfig;
use crate::proposal::{CutProposal, CutProposalPart};
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
}

impl CipherBftContext {
    /// Create a new context.
    pub fn new(
        config: ConsensusConfig,
        validator_set: ConsensusValidatorSet,
        initial_height: ConsensusHeight,
    ) -> Self {
        Self {
            config,
            validator_set,
            initial_height,
        }
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

    /// Deterministic round-robin proposer selection.
    pub fn proposer_at_round(&self, round: Round) -> Option<ConsensusAddress> {
        let count = self.validator_set.len();
        if count == 0 {
            return None;
        }

        // Use round index modulo validator count; nil rounds map to first validator.
        let idx = match round.as_i64() {
            x if x < 0 => 0,
            x => (x as usize) % count,
        };
        self.validator_set.as_slice().get(idx).map(|v| v.address)
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
        _height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        let count = validator_set.len();
        let idx = match round.as_i64() {
            x if x < 0 => 0,
            x => (x as usize) % count.max(1),
        };
        validator_set
            .as_slice()
            .get(idx)
            .expect("validator_set must not be empty")
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
        ConsensusVote::new(height, round, value_id, VoteType::Prevote, address)
    }

    fn new_precommit(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<ValueId<Self>>,
        address: Self::Address,
    ) -> Self::Vote {
        ConsensusVote::new(height, round, value_id, VoteType::Precommit, address)
    }
}
