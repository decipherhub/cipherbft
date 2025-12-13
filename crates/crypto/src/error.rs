//! Cryptographic error types

use thiserror::Error;

/// BLS12-381 cryptographic errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BlsError {
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

    /// Signature aggregation failed
    #[error("signature aggregation failed")]
    AggregationFailed,

    /// Empty input for aggregation
    #[error("cannot aggregate empty signature list")]
    EmptyAggregation,

    /// Invalid message length
    #[error("invalid message length")]
    InvalidMessageLength,
}
