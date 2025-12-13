//! Cryptographic primitives for CipherBFT
//!
//! This crate provides:
//! - BLS12-381 signatures for DCL (Data Chain Layer)
//! - Ed25519 signatures for CL (Consensus Layer, via Malachite)
//! - Domain separation for cross-context security

pub mod bls;
pub mod error;

pub use bls::{
    BlsAggregateSignature, BlsKeyPair, BlsPublicKey, BlsSecretKey, BlsSignature, DST_ATTESTATION,
    DST_CAR,
};
pub use error::BlsError;
