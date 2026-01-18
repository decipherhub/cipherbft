//! Keystore error types

use thiserror::Error;

/// Errors that can occur during keystore operations
#[derive(Error, Debug)]
pub enum KeystoreError {
    /// Invalid passphrase provided during decryption
    #[error("invalid passphrase: checksum verification failed")]
    InvalidPassphrase,

    /// Checksum verification failed (corrupted keystore)
    #[error("checksum verification failed: keystore may be corrupted")]
    ChecksumMismatch,

    /// Unsupported KDF function
    #[error("unsupported KDF function: {0}")]
    UnsupportedKdf(String),

    /// Unsupported cipher function
    #[error("unsupported cipher function: {0}")]
    UnsupportedCipher(String),

    /// Unsupported checksum function
    #[error("unsupported checksum function: {0}")]
    UnsupportedChecksum(String),

    /// Invalid KDF parameters
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(String),

    /// Invalid cipher parameters
    #[error("invalid cipher parameters: {0}")]
    InvalidCipherParams(String),

    /// Key derivation failed
    #[error("key derivation failed: {0}")]
    KdfError(String),

    /// Encryption/decryption failed
    #[error("cipher operation failed: {0}")]
    CipherError(String),

    /// File I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Invalid secret length
    #[error("invalid secret length: expected {expected}, got {actual}")]
    InvalidSecretLength { expected: usize, actual: usize },

    /// Passphrase too weak
    #[error("passphrase too weak: {0}")]
    WeakPassphrase(String),

    /// Invalid hex encoding
    #[error("invalid hex encoding: {0}")]
    HexError(String),

    /// Keystore file already exists
    #[error("keystore already exists at path: {0}")]
    AlreadyExists(String),
}

/// Result type for keystore operations
pub type KeystoreResult<T> = Result<T, KeystoreError>;
