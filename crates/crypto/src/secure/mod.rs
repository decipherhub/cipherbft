//! Secure memory handling for cryptographic material
//!
//! This module provides memory-safe containers for private key material with:
//! - Automatic zeroing on drop via `zeroize`
//! - Debug output masking to prevent log exposure
//! - Prevention of accidental cloning
//!
//! # Security Properties
//!
//! - Keys are zeroized when dropped (even on panic)
//! - Debug output shows `[REDACTED]` instead of secret bytes
//! - Clone is intentionally NOT implemented to prevent accidental copies
//!
//! # Example
//!
//! ```rust,ignore
//! use cipherbft_crypto::secure::SecureKeyMaterial;
//!
//! let material = SecureKeyMaterial::new(ed25519_seed, bls_seed);
//! // Use the material...
//! drop(material); // Memory is automatically zeroed
//! ```

mod material;
mod secret;

pub use material::{DerivationInfo, SecureKeyMaterial};
pub use secret::{IntoSecret, SecretArray, SecretBytes, SecretString};
