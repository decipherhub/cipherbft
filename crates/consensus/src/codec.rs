//! Codec for serializing/deserializing Malachite consensus messages.
//!
//! This module implements the Codec trait for encoding and decoding consensus
//! messages (Proposals, Votes, ProposalParts) for network transmission and WAL storage.
//!
//! Uses borsh serialization as Malachite types have borsh support enabled.

use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Bytes;
use std::fmt;

use crate::context::CipherBftContext;
use crate::proposal::CutProposalPart;
use informalsystems_malachitebft_app::streaming::StreamMessage;
use informalsystems_malachitebft_app::types::ProposedValue;
use informalsystems_malachitebft_app::types::SignedConsensusMsg;
use informalsystems_malachitebft_codec::Codec;
use informalsystems_malachitebft_core_consensus::LivenessMsg;
use informalsystems_malachitebft_sync::{
    Request as SyncRequest, Response as SyncResponse, Status as SyncStatus,
};

/// Error type for codec operations.
#[derive(Debug)]
pub struct CodecError(String);

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "codec error: {}", self.0)
    }
}

impl std::error::Error for CodecError {}

/// Borsh-based codec implementation for CipherBFT consensus messages.
///
/// This codec implements all required Codec<T> traits for Malachite's
/// ConsensusCodec, WalCodec, and SyncCodec blanket implementations.
#[derive(Clone, Debug, Default)]
pub struct CipherBftCodec;

impl CipherBftCodec {
    pub fn new() -> Self {
        Self
    }
}

// Helper macro to implement Codec for borsh-serializable types
macro_rules! impl_borsh_codec {
    ($type:ty, $name:expr) => {
        impl Codec<$type> for CipherBftCodec
        where
            $type: BorshSerialize + BorshDeserialize,
        {
            type Error = CodecError;

            fn decode(&self, bytes: Bytes) -> Result<$type, Self::Error> {
                BorshDeserialize::try_from_slice(&bytes)
                    .map_err(|e| CodecError(format!("failed to decode {}: {}", $name, e)))
            }

            fn encode(&self, msg: &$type) -> Result<Bytes, Self::Error> {
                let bytes = borsh::to_vec(msg)
                    .map_err(|e| CodecError(format!("failed to encode {}: {}", $name, e)))?;
                Ok(Bytes::from(bytes))
            }
        }
    };
}

// Implement Codec for all required message types
impl_borsh_codec!(SignedConsensusMsg<CipherBftContext>, "SignedConsensusMsg");
impl_borsh_codec!(StreamMessage<CutProposalPart>, "StreamMessage");
impl_borsh_codec!(ProposedValue<CipherBftContext>, "ProposedValue");
impl_borsh_codec!(CutProposalPart, "CutProposalPart");
impl_borsh_codec!(LivenessMsg<CipherBftContext>, "LivenessMsg");
impl_borsh_codec!(SyncStatus<CipherBftContext>, "SyncStatus");
impl_borsh_codec!(SyncRequest<CipherBftContext>, "SyncRequest");
impl_borsh_codec!(SyncResponse<CipherBftContext>, "SyncResponse");

/// Type alias for the consensus codec used throughout the codebase.
pub type ConsensusCodec = CipherBftCodec;
