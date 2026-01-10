//! Codec for serializing/deserializing Malachite consensus messages.
//!
//! This module implements the Codec trait for encoding and decoding consensus
//! messages (Proposals, Votes, ProposalParts) for network transmission and WAL storage.

use crate::context::CipherBftContext;
use anyhow::Result;
use informalsystems_malachitebft_app::types::SignedConsensusMsg;
use informalsystems_malachitebft_app::streaming::StreamMessage;
use informalsystems_malachitebft_codec::Codec as MalachiteCodec;
use crate::proposal::CutProposalPart;

/// Codec implementation for CipherBFT consensus messages.
///
/// Uses Malachite's Codec trait for message serialization.
#[derive(Clone, Debug, Default)]
pub struct ConsensusCodec;

impl MalachiteCodec<CipherBftContext> for ConsensusCodec {
    fn encode_signed_msg(&self, msg: &SignedConsensusMsg<CipherBftContext>) -> Result<Vec<u8>> {
        // Use bincode for serialization (simple, fast, consistent with DCL)
        bincode::serialize(msg).map_err(|e| anyhow::anyhow!("Encoding error: {}", e))
    }

    fn decode_signed_msg(&self, bytes: &[u8]) -> Result<SignedConsensusMsg<CipherBftContext>> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!("Decoding error: {}", e))
    }

    fn encode_stream_msg(&self, msg: &StreamMessage<CutProposalPart>) -> Result<Vec<u8>> {
        bincode::serialize(msg).map_err(|e| anyhow::anyhow!("Stream encoding error: {}", e))
    }

    fn decode_stream_msg(&self, bytes: &[u8]) -> Result<StreamMessage<CutProposalPart>> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!("Stream decoding error: {}", e))
    }
}
