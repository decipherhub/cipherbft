//! Consensus Layer scaffolding
//!
//! This crate hosts the Malachite integration surface area. Malachite
//! dependencies are optional and gated behind the `malachite` feature so
//! existing builds remain unaffected while we wire up the consensus layer.

pub mod config;
pub mod error;
pub mod types;

pub use error::ConsensusError;

#[cfg(feature = "malachite")]
pub mod context;
#[cfg(feature = "malachite")]
pub mod engine;
#[cfg(feature = "malachite")]
pub mod proposal;
#[cfg(feature = "malachite")]
pub mod signing;
#[cfg(feature = "malachite")]
pub mod validator_set;
#[cfg(feature = "malachite")]
pub mod vote;
#[cfg(feature = "malachite")]
pub mod host;
#[cfg(feature = "malachite")]
pub mod codec;
#[cfg(feature = "malachite")]
pub mod network;
#[cfg(feature = "malachite")]
pub mod wal;

pub use config::ConsensusConfig;
pub use types::{ConsensusHeight, ConsensusRound, ConsensusValue};

#[cfg(feature = "malachite")]
pub use context::CipherBftContext;
#[cfg(feature = "malachite")]
pub use engine::{
    create_context, create_engine_config, default_consensus_params,
    default_engine_config_single_part, EngineHandles, MalachiteEngineBuilder,
};
#[cfg(feature = "malachite")]
pub use proposal::{CutProposal, CutProposalPart};
#[cfg(feature = "malachite")]
pub use signing::{ConsensusSigner, ConsensusSigningProvider};
#[cfg(feature = "malachite")]
pub use validator_set::{ConsensusValidator, ConsensusValidatorSet};
#[cfg(feature = "malachite")]
pub use vote::ConsensusVote;
#[cfg(feature = "malachite")]
pub use host::spawn_host;
#[cfg(feature = "malachite")]
pub use codec::ConsensusCodec;
#[cfg(feature = "malachite")]
pub use network::spawn_network;
#[cfg(feature = "malachite")]
pub use wal::spawn_wal;
