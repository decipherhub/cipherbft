use std::io::{Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use cipherbft_data_chain::Cut;
use informalsystems_malachitebft_core_types::{
    Proposal as MalachiteProposal, ProposalPart as MalachiteProposalPart, Round,
};

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

impl BorshSerialize for CutProposal {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.height.serialize(writer)?;
        (self.round.as_i64() as u32).serialize(writer)?;
        self.value.serialize(writer)?;
        (self.pol_round.as_i64() as u32).serialize(writer)?;
        self.proposer.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for CutProposal {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let height = ConsensusHeight::deserialize_reader(reader)?;
        let round_val: u32 = BorshDeserialize::deserialize_reader(reader)?;
        let round = Round::new(round_val);
        let value = ConsensusValue::deserialize_reader(reader)?;
        let pol_round_val: u32 = BorshDeserialize::deserialize_reader(reader)?;
        let pol_round = Round::new(pol_round_val);
        let proposer = ConsensusAddress::deserialize_reader(reader)?;
        Ok(Self {
            height,
            round,
            value,
            pol_round,
            proposer,
        })
    }
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

    fn value(
        &self,
    ) -> &<CipherBftContext as informalsystems_malachitebft_core_types::Context>::Value {
        &self.value
    }

    fn take_value(
        self,
    ) -> <CipherBftContext as informalsystems_malachitebft_core_types::Context>::Value {
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

impl BorshSerialize for CutProposalPart {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Use bincode for Cut (contains HashMap which doesn't implement borsh)
        let cut_bytes = bincode::serialize(&self.cut)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        (cut_bytes.len() as u32).serialize(writer)?;
        writer.write_all(&cut_bytes)?;
        self.first.serialize(writer)?;
        self.last.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for CutProposalPart {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let len = u32::deserialize_reader(reader)? as usize;
        let mut cut_bytes = vec![0u8; len];
        reader.read_exact(&mut cut_bytes)?;
        let cut: Cut = bincode::deserialize(&cut_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let first = bool::deserialize_reader(reader)?;
        let last = bool::deserialize_reader(reader)?;
        Ok(Self { cut, first, last })
    }
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
        self.cut.hash() == other.cut.hash() && self.first == other.first && self.last == other.last
    }
}

impl Eq for CutProposalPart {}
