//! Core type definitions for CipherBFT
//!
//! This crate provides foundational types used across all CipherBFT components.
//!
//! # Genesis Formats
//!
//! This crate supports two genesis file formats:
//!
//! - **Native format** (`genesis` module): CipherBFT-native format for existing tooling
//! - **Geth-compatible format** (`geth` module): Ethereum-compatible format with `cipherbft` extension
//!
//! The Geth-compatible format is preferred for new deployments as it enables
//! integration with standard EVM tooling (Foundry, Hardhat, etc.).

mod hash;
mod height;
mod validator;

pub mod genesis;
pub mod geth;

pub use genesis::{Genesis, GenesisError, GenesisValidator};
pub use hash::Hash;
pub use height::Height;
pub use validator::{ValidatorId, VALIDATOR_ID_SIZE};
