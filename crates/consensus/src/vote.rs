use std::io::{Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use informalsystems_malachitebft_core_types::{
    NilOrVal, Round, SignedExtension, Vote as MalachiteVote, VoteType,
};

use crate::context::CipherBftContext;
use crate::signing::ConsensusSignature;
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

impl BorshSerialize for ConsensusVote {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.height.serialize(writer)?;
        (self.round.as_i64() as u32).serialize(writer)?;
        // NilOrVal
        match &self.value {
            NilOrVal::Nil => 0u8.serialize(writer)?,
            NilOrVal::Val(id) => {
                1u8.serialize(writer)?;
                id.serialize(writer)?;
            }
        }
        // VoteType
        match self.vote_type {
            VoteType::Prevote => 0u8.serialize(writer)?,
            VoteType::Precommit => 1u8.serialize(writer)?,
        }
        self.validator.serialize(writer)?;
        // Extension
        match &self.extension {
            None => 0u8.serialize(writer)?,
            Some(ext) => {
                1u8.serialize(writer)?;
                ext.message.serialize(writer)?;
                ext.signature.serialize(writer)?;
            }
        }
        Ok(())
    }
}

impl BorshDeserialize for ConsensusVote {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let height = ConsensusHeight::deserialize_reader(reader)?;
        let round_val: u32 = BorshDeserialize::deserialize_reader(reader)?;
        let round = Round::new(round_val);
        let value = match u8::deserialize_reader(reader)? {
            0 => NilOrVal::Nil,
            1 => NilOrVal::Val(ConsensusValueId::deserialize_reader(reader)?),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid NilOrVal tag",
                ))
            }
        };
        let vote_type = match u8::deserialize_reader(reader)? {
            0 => VoteType::Prevote,
            1 => VoteType::Precommit,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid VoteType tag",
                ))
            }
        };
        let validator = ConsensusAddress::deserialize_reader(reader)?;
        let extension = match u8::deserialize_reader(reader)? {
            0 => None,
            1 => {
                let message: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
                let signature = ConsensusSignature::deserialize_reader(reader)?;
                Some(SignedExtension { message, signature })
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid extension tag",
                ))
            }
        };
        Ok(Self {
            height,
            round,
            value,
            vote_type,
            validator,
            extension,
        })
    }
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
