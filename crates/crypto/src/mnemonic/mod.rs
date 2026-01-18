//! Mnemonic-based key generation and recovery for CipherBFT
//!
//! This module provides BIP-39 mnemonic phrase generation and BIP-32 hierarchical
//! deterministic (HD) key derivation for CipherBFT validators.
//!
//! # Derivation Path
//!
//! CipherBFT uses the following derivation path structure:
//! ```text
//! m / 12381 / 8888 / account / key_type
//! ```
//!
//! Where:
//! - `12381` = BLS12-381 curve identifier (EIP-2333)
//! - `8888` = CipherBFT application identifier
//! - `account` = Validator account index (0, 1, 2, ...)
//! - `key_type` = 0 for consensus (Ed25519), 1 for data chain (BLS)
//!
//! # Example
//!
//! ```rust
//! use cipherbft_crypto::mnemonic::{Mnemonic, derive_validator_keys};
//!
//! // Generate a new mnemonic
//! let mnemonic = Mnemonic::generate().unwrap();
//! println!("Backup phrase: {}", mnemonic.phrase());
//!
//! // Derive keys for account 0
//! let keys = derive_validator_keys(&mnemonic, 0, None).unwrap();
//! println!("Validator ID: {:?}", keys.validator_id());
//! ```
//!
//! # Security
//!
//! - Mnemonic phrases should be stored securely offline
//! - The same mnemonic will always produce the same keys
//! - Use an optional passphrase for additional security

mod derive;
mod error;
mod generate;

pub use derive::{
    derive_bls_key, derive_ed25519_key, derive_validator_keys, DerivationConfig,
    CIPHERBFT_COIN_TYPE, DEFAULT_DERIVATION_PATH_BLS, DEFAULT_DERIVATION_PATH_ED25519,
};
pub use error::{MnemonicError, MnemonicResult};
pub use generate::Mnemonic;
