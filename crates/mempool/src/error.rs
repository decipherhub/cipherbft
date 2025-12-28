//! Error types for mempool operations

use thiserror::Error;

/// Mempool error types
#[derive(Error, Debug, Clone)]
pub enum MempoolError {
    #[error("Transaction already exists in pool")]
    TransactionAlreadyExists,

    #[error("Sender account is full")]
    SenderAccountFull,

    #[error("Insufficient gas price")]
    InsufficientGasPrice,

    #[error("Nonce too low: current={current}, got={provided}")]
    NonceTooLow { current: u64, provided: u64 },

    #[error("Nonce gap exceeds maximum: gap={gap} > max={max}")]
    NonceGapExceeded { gap: u64, max: u64 },

    #[error("Sender not found")]
    SenderNotFound,

    #[error("Transaction not found")]
    TransactionNotFound,

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Pool overflow")]
    PoolOverflow,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}
