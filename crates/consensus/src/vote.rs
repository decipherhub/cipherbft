use informalsystems_malachitebft_core_types::{
    NilOrVal, Round, SignedExtension, Vote as MalachiteVote, VoteType,
};

use crate::context::CipherBftContext;
use crate::types::{ConsensusHeight, ConsensusValueId};
use crate::validator_set::ConsensusAddress;

/// Consensus vote (prevote/precommit).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsensusVote {
    pub height: ConsensusHeight,
    pub round: Round,
    pub value: NilOrVal<ConsensusValueId>,
    pub vote_type: VoteType,
    pub validator: ConsensusAddress,
    pub extension: Option<SignedExtension<CipherBftContext>>,
}

impl ConsensusVote {
    pub fn new(
        height: ConsensusHeight,
        round: Round,
        value: NilOrVal<ConsensusValueId>,
        vote_type: VoteType,
        validator: ConsensusAddress,
    ) -> Self {
        Self {
            height,
            round,
            value,
            vote_type,
            validator,
            extension: None,
        }
    }
}

impl MalachiteVote<CipherBftContext> for ConsensusVote {
    fn height(&self) -> ConsensusHeight {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &NilOrVal<ConsensusValueId> {
        &self.value
    }

    fn take_value(self) -> NilOrVal<ConsensusValueId> {
        self.value
    }

    fn vote_type(&self) -> VoteType {
        self.vote_type
    }

    fn validator_address(&self) -> &ConsensusAddress {
        &self.validator
    }

    fn extension(&self) -> Option<&SignedExtension<CipherBftContext>> {
        self.extension.as_ref()
    }

    fn take_extension(&mut self) -> Option<SignedExtension<CipherBftContext>> {
        self.extension.take()
    }

    fn extend(self, extension: SignedExtension<CipherBftContext>) -> Self {
        let mut vote = self;
        vote.extension = Some(extension);
        vote
    }
}
