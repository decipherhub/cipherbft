//! Error types for the execution layer.
//!
//! This module defines the error types used throughout the execution layer,
//! including database errors, EVM execution errors, and state management errors.

use alloy_primitives::{Address, B256};

/// Result type alias for execution layer operations.
pub type Result<T> = std::result::Result<T, ExecutionError>;

/// Main error type for the execution layer.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    /// Database operation failed.
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    /// EVM execution failed.
    #[error("EVM execution error: {0}")]
    Evm(String),

    /// Transaction is invalid.
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// State root computation failed.
    #[error("State root computation failed: {0}")]
    StateRoot(String),

    /// Rollback operation failed.
    #[error("Rollback failed: no snapshot at block {0}")]
    RollbackNoSnapshot(u64),

    /// Configuration is invalid.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Precompile execution failed.
    #[error("Precompile error: {0}")]
    Precompile(String),

    /// Block is invalid.
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    /// State is inconsistent.
    #[error("Inconsistent state: {0}")]
    InconsistentState(String),

    /// Internal error that should not occur.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Error type for database operations.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    /// MDBX database error.
    #[error("MDBX error: {0}")]
    Mdbx(String),

    /// Account not found in database.
    #[error("Account not found: {0}")]
    AccountNotFound(Address),

    /// Code not found in database.
    #[error("Code not found: {0}")]
    CodeNotFound(B256),

    /// Block hash not found in database.
    #[error("Block hash not found: {0}")]
    BlockHashNotFound(u64),

    /// Snapshot not found at specified block.
    #[error("Snapshot not found at block {0}")]
    SnapshotNotFound(u64),

    /// Storage slot not found.
    #[error("Storage not found for address {0}, slot {1}")]
    StorageNotFound(Address, B256),

    /// Database corruption detected.
    #[error("Database corruption detected: {0}")]
    Corruption(String),

    /// Transaction failed.
    #[error("Database transaction error: {0}")]
    Transaction(String),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl ExecutionError {
    /// Create an invalid transaction error.
    pub fn invalid_transaction(msg: impl Into<String>) -> Self {
        Self::InvalidTransaction(msg.into())
    }

    /// Create an EVM execution error.
    pub fn evm(msg: impl Into<String>) -> Self {
        Self::Evm(msg.into())
    }

    /// Create a state root computation error.
    pub fn state_root(msg: impl Into<String>) -> Self {
        Self::StateRoot(msg.into())
    }

    /// Create a configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create an internal error.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl DatabaseError {
    /// Create an MDBX error.
    pub fn mdbx(msg: impl Into<String>) -> Self {
        Self::Mdbx(msg.into())
    }

    /// Create a corruption error.
    pub fn corruption(msg: impl Into<String>) -> Self {
        Self::Corruption(msg.into())
    }

    /// Create a transaction error.
    pub fn transaction(msg: impl Into<String>) -> Self {
        Self::Transaction(msg.into())
    }

    /// Create a serialization error.
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization(msg.into())
    }
}
