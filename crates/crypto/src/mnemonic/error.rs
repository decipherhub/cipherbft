//! Error types for mnemonic operations

use thiserror::Error;

/// Result type for mnemonic operations
pub type MnemonicResult<T> = Result<T, MnemonicError>;

/// Errors that can occur during mnemonic operations
#[derive(Debug, Error)]
pub enum MnemonicError {
    /// Invalid mnemonic phrase (wrong word count or invalid words)
    #[error("invalid mnemonic phrase: {0}")]
    InvalidPhrase(String),

    /// Passphrase is too long
    #[error("passphrase is too long (max 256 bytes)")]
    PassphraseTooLong,

    /// Key derivation failed
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),

    /// Invalid derivation path
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    /// Entropy generation failed
    #[error("entropy generation failed")]
    EntropyError,

    /// Internal cryptographic error
    #[error("cryptographic error: {0}")]
    CryptoError(String),
}

impl From<bip39::Error> for MnemonicError {
    fn from(err: bip39::Error) -> Self {
        MnemonicError::InvalidPhrase(err.to_string())
    }
}
