//! Core types for CipherBFT consensus engine.
//!
//! This crate provides fundamental data structures used throughout the CipherBFT
//! consensus implementation, including blocks, votes, validators, and consensus state.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

pub mod block;
pub mod hash;
pub mod height;
pub mod round;
pub mod validator;
pub mod vote;

pub use block::{Block, BlockData, BlockHeader, CarMetadata, CutMetadata, ValidatorSignature};
pub use hash::{Hash, HashError};
pub use height::{Height, HeightError};
pub use round::Round;
pub use validator::{Validator, ValidatorSet, ValidatorSetError};
pub use vote::{Vote, VoteType};
