//! Cryptographic primitives for CipherBFT.
//!
//! This crate provides Ed25519 signature operations and hashing utilities
//! for the CipherBFT consensus engine.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

pub mod hash;
pub mod signature;

pub use hash::{hash, hash_block, hash_tx, merkle_root, merkle_root_from_txs};
pub use signature::{Address, KeyPair, PrivateKey, PublicKey, Signature, SignatureError};
