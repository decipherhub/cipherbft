//! Cryptographic error types

use thiserror::Error;

/// Unified cryptographic error type
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid secret key bytes
    #[error("invalid secret key bytes")]
    InvalidSecretKey,

    /// Invalid public key bytes
    #[error("invalid public key bytes")]
    InvalidPublicKey,

    /// Invalid signature bytes
    #[error("invalid signature bytes")]
    InvalidSignature,

    /// Signature verification failed
    #[error("signature verification failed")]
    VerificationFailed,

    /// Signature aggregation failed (BLS only)
    #[error("signature aggregation failed")]
    AggregationFailed,

    /// Empty input for aggregation (BLS only)
    #[error("cannot aggregate empty signature list")]
    EmptyAggregation,

    /// Invalid message length
    #[error("invalid message length")]
    InvalidMessageLength,
}

/// BLS12-381 specific errors (alias for backwards compatibility)
pub type BlsError = CryptoError;
