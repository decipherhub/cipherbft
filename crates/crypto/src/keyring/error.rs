//! Keyring error types

use std::io;
use thiserror::Error;

/// Result type for keyring operations
pub type KeyringResult<T> = Result<T, KeyringError>;

/// Errors that can occur during keyring operations
#[derive(Error, Debug)]
pub enum KeyringError {
    /// Invalid backend name
    #[error("invalid keyring backend: {0}. Valid options: file, os, test")]
    InvalidBackend(String),

    /// Backend not available (e.g., OS keyring without feature)
    #[error("keyring backend not available: {0}")]
    BackendNotAvailable(String),

    /// Passphrase required but not provided
    #[error("passphrase is required for this keyring backend")]
    PassphraseRequired,

    /// Key not found
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Key already exists
    #[error("key already exists: {0}")]
    KeyAlreadyExists(String),

    /// Invalid passphrase
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// Keystore format error
    #[error("keystore format error: {0}")]
    FormatError(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Hex decoding error
    #[error("hex decoding error: {0}")]
    HexError(String),

    /// Underlying keystore error
    #[error("keystore error: {0}")]
    KeystoreError(#[from] crate::keystore::KeystoreError),

    /// OS keyring error
    #[cfg(feature = "keychain")]
    #[error("OS keyring error: {0}")]
    OsKeyringError(String),

    /// Permission denied
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid key data
    #[error("invalid key data: {0}")]
    InvalidKeyData(String),
}
