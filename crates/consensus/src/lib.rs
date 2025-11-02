//! Autobahn BFT consensus engine implementation.
//!
//! This crate implements the Autobahn BFT consensus algorithm with Car/Cut
//! data availability proofs and PBFT-style voting.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

pub mod car;
pub mod engine;
pub mod proposal;
pub mod state_machine;
pub mod timeouts;
pub mod vote_set;

pub use engine::ConsensusEngine;
pub use state_machine::{ConsensusState, ConsensusStep};
