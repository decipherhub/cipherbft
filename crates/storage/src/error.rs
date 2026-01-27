//! Storage error types

use cipherbft_types::{Hash, ValidatorId};
use thiserror::Error;

/// Storage operation errors
#[derive(Debug, Error)]
pub enum StorageError {
    /// Batch not found
    #[error("batch not found: {0}")]
    BatchNotFound(Hash),

    /// Car not found
    #[error("car not found for validator {0} at position {1}")]
    CarNotFound(ValidatorId, u64),

    /// Car not found by hash
    #[error("car not found with hash: {0}")]
    CarNotFoundByHash(Hash),

    /// Attestation not found
    #[error("attestation not found for car: {0}")]
    AttestationNotFound(Hash),

    /// Cut not found
    #[error("cut not found at height {0}")]
    CutNotFound(u64),

    /// Duplicate entry
    #[error("duplicate entry: {0}")]
    DuplicateEntry(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// WAL error
    #[error("wal error: {0}")]
    Wal(String),

    /// Transaction error
    #[error("transaction error: {0}")]
    Transaction(String),

    /// Database error
    #[error("database error: {0}")]
    Database(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Invalid state error (for persistent state operations)
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// State recovery error
    #[error("state recovery error: {0}")]
    StateRecovery(String),
}

/// Result type for storage operations
pub type Result<T> = std::result::Result<T, StorageError>;
