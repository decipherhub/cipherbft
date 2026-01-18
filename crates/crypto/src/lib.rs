//! Cryptographic primitives for CipherBFT
//!
//! This crate provides:
//! - BLS12-381 signatures for DCL (Data Chain Layer) - Car/Attestation signing
//! - Ed25519 signatures for CL (Consensus Layer, via Malachite) - Voting/Proposals
//! - ValidatorKeys for dual key management
//! - Domain separation for cross-context security
//! - Keyring backends for secure key storage (file, OS, test)

pub mod bls;
pub mod ed25519;
pub mod error;
pub mod keyring;
pub mod keys;
pub mod keystore;
pub mod mnemonic;
pub mod secure;

// BLS12-381 exports (DCL)
pub use bls::{
    BlsAggregateSignature, BlsKeyPair, BlsPublicKey, BlsSecretKey, BlsSignature, DST_ATTESTATION,
    DST_CAR,
};

// Ed25519 exports (CL)
pub use ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

// Dual key exports
pub use keys::{KeystorePaths, ValidatorKeys, ValidatorPublicKeys};

// Error exports
pub use error::{BlsError, CryptoError};

// Secure memory exports
pub use secure::{
    DerivationInfo, ExposeSecret, IntoSecret, SecretArray, SecretBytes, SecretString,
    SecureKeyMaterial,
};

// Keystore exports
pub use keystore::{EncryptedKeystore, KeystoreBuilder, KeystoreError};

// Mnemonic exports
pub use mnemonic::{derive_validator_keys, Mnemonic, MnemonicError};

// Keyring exports
#[cfg(feature = "keychain")]
pub use keyring::OsKeyring;
pub use keyring::{
    FileKeyring, KeyMetadata, Keyring, KeyringBackend, KeyringBackendTrait, KeyringError,
    KeyringResult, TestKeyring,
};
