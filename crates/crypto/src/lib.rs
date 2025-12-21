//! Cryptographic primitives for CipherBFT
//!
//! This crate provides:
//! - BLS12-381 signatures for DCL (Data Chain Layer) - Car/Attestation signing
//! - Ed25519 signatures for CL (Consensus Layer, via Malachite) - Voting/Proposals
//! - ValidatorKeys for dual key management
//! - Domain separation for cross-context security

pub mod bls;
pub mod ed25519;
pub mod error;
pub mod keys;

// BLS12-381 exports (DCL)
pub use bls::{
    BlsAggregateSignature, BlsKeyPair, BlsPublicKey, BlsSecretKey, BlsSignature, DST_ATTESTATION,
    DST_CAR,
};

// Ed25519 exports (CL)
pub use ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

// Dual key exports
pub use keys::{ValidatorKeys, ValidatorPublicKeys};

// Error exports
pub use error::{BlsError, CryptoError};
