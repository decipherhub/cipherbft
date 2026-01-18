//! EIP-2335 compatible encrypted keystore implementation
//!
//! This module provides secure key storage following the EIP-2335 specification
//! used by Ethereum 2.0 validators. The format supports:
//!
//! - Password-based encryption using scrypt KDF
//! - AES-128-CTR symmetric encryption
//! - SHA-256 checksum verification
//! - JSON serialization for portability
//!
//! # Security Properties
//!
//! - Keys are encrypted at rest with a user passphrase
//! - scrypt KDF makes brute-force attacks expensive
//! - Checksum prevents tampering detection
//! - UUID provides unique identification
//!
//! # Example
//!
//! ```rust,ignore
//! use cipherbft_crypto::keystore::{EncryptedKeystore, KeystoreBuilder};
//!
//! // Create a new keystore
//! let keystore = KeystoreBuilder::new()
//!     .secret(&secret_key_bytes)
//!     .passphrase("my-strong-passphrase")
//!     .description("Validator consensus key")
//!     .build()?;
//!
//! // Save to file
//! keystore.save("./keys/consensus.json")?;
//!
//! // Load and decrypt
//! let loaded = EncryptedKeystore::load("./keys/consensus.json")?;
//! let decrypted = loaded.decrypt("my-strong-passphrase")?;
//! ```

mod checksum;
mod cipher;
mod encrypted;
mod error;
mod kdf;

pub use checksum::{compute_checksum, verify_checksum, ChecksumModule};
pub use cipher::{decrypt_secret, encrypt_secret, CipherModule};
pub use encrypted::{EncryptedKeystore, KeystoreBuilder};
pub use error::KeystoreError;
pub use kdf::{scrypt_derive_key, KdfModule, KdfParams};
