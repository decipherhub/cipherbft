use cipherbft_data_chain::Cut;
use informalsystems_malachitebft_core_types::{Proposal as MalachiteProposal, ProposalPart as MalachiteProposalPart, Round};

use crate::context::CipherBftContext;
use crate::types::{ConsensusHeight, ConsensusValue};
use crate::validator_set::ConsensusAddress;

/// Proposal wrapper carrying a cut and metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutProposal {
    pub height: ConsensusHeight,
    pub round: Round,
    pub value: ConsensusValue,
    pub pol_round: Round,
    pub proposer: ConsensusAddress,
}

impl CutProposal {
    pub fn new(
        height: ConsensusHeight,
        round: Round,
        value: ConsensusValue,
        pol_round: Round,
        proposer: ConsensusAddress,
    ) -> Self {
        Self {
            height,
            round,
            value,
            pol_round,
            proposer,
        }
    }

    pub fn into_cut(self) -> Cut {
        self.value.into_cut()
    }
}

impl MalachiteProposal<CipherBftContext> for CutProposal {
    fn height(&self) -> ConsensusHeight {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &<CipherBftContext as informalsystems_malachitebft_core_types::Context>::Value {
        &self.value
    }

    fn take_value(self) -> <CipherBftContext as informalsystems_malachitebft_core_types::Context>::Value {
        self.value
    }

    fn pol_round(&self) -> Round {
        self.pol_round
    }

    fn validator_address(&self) -> &ConsensusAddress {
        &self.proposer
    }
}

/// Single-part proposal chunk.
#[derive(Clone, Debug)]
pub struct CutProposalPart {
    pub cut: Cut,
    pub first: bool,
    pub last: bool,
}

impl CutProposalPart {
    pub fn single(cut: Cut) -> Self {
        Self {
            cut,
            first: true,
            last: true,
        }
    }
}

impl MalachiteProposalPart<CipherBftContext> for CutProposalPart {
    fn is_first(&self) -> bool {
        self.first
    }

    fn is_last(&self) -> bool {
        self.last
    }
}

impl PartialEq for CutProposalPart {
    fn eq(&self, other: &Self) -> bool {
        self.cut.hash() == other.cut.hash()
            && self.first == other.first
            && self.last == other.last
    }
}

impl Eq for CutProposalPart {}
