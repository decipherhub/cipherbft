//! Error types for mempool operations
//!
//! MP-1: keep the data structure minimal, wrap Reth's PoolError, and expose
//! only the BFT policy errors we need.

use reth_transaction_pool::error::PoolError;
use thiserror::Error;

/// Mempool error types (expanded for MP-2)
#[derive(Error, Debug)]
pub enum MempoolError {
    /// Bubble up errors coming from the underlying Reth pool.
    #[error(transparent)]
    Pool(#[from] PoolError),

    /// Gas price below policy threshold.
    #[error("Insufficient gas price: got {got}, min {min}")]
    InsufficientGasPrice { got: u128, min: u128 },

    /// Nonce gap exceeds configured maximum.
    #[error("Nonce gap exceeds maximum: gap={gap} > max={max}")]
    NonceGapExceeded { gap: u64, max: u64 },

    /// Invalid signature.
    #[error("Invalid transaction signature")]
    InvalidSignature,

    /// Nonce too low (already executed).
    #[error("Nonce too low: tx nonce {tx_nonce}, current {current_nonce}")]
    NonceTooLow { tx_nonce: u64, current_nonce: u64 },

    /// Insufficient balance for gas.
    #[error("Insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u128, have: u128 },

    /// Gas limit too high.
    #[error("Gas limit too high: {gas_limit} > {max}")]
    GasLimitTooHigh { gas_limit: u64, max: u64 },

    /// Transaction size exceeds limit.
    #[error("Transaction too large: {size} > {max}")]
    OversizedTransaction { size: usize, max: usize },

    /// Failed to convert into pool-specific transaction type.
    #[error("Transaction conversion failed: {0}")]
    Conversion(String),

    /// Internal error marker.
    #[error("Internal error: {0}")]
    Internal(String),
}
