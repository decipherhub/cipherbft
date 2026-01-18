//! Consensus layer error types

use thiserror::Error;

/// Maximum number of validators allowed in a validator set.
/// This limit prevents OOM attacks via unbounded deserialization.
/// Set to 10,000 which is well above any practical BFT validator set size.
pub const MAX_VALIDATORS: usize = 10_000;

/// Maximum number of batch digests allowed in a single Car.
/// Each worker can produce at most one batch per Car, and we support up to 8 workers.
pub const MAX_BATCH_DIGESTS: usize = 256;

/// Maximum number of transactions allowed in a single batch.
/// This prevents OOM from maliciously large batch claims.
pub const MAX_TRANSACTIONS_PER_BATCH: usize = 100_000;

/// Maximum size of a single transaction in bytes (10 MB).
pub const MAX_TRANSACTION_SIZE: usize = 10 * 1024 * 1024;

/// Maximum total size of a batch in bytes (100 MB).
pub const MAX_BATCH_SIZE: usize = 100 * 1024 * 1024;

/// Maximum number of hash digests in a sync request.
pub const MAX_SYNC_DIGESTS: usize = 10_000;

/// Errors that can occur during consensus operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// Validator set cannot be empty for consensus operations.
    #[error("validator set cannot be empty")]
    EmptyValidatorSet,

    /// Invalid configuration provided.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Validator set not found for the specified height.
    #[error("validator set not found for height {height}")]
    ValidatorSetNotFound {
        /// The height for which no validator set was found.
        height: u64,
    },

    /// Failed to spawn the host actor.
    #[error("failed to spawn host actor: {0}")]
    HostSpawnError(String),

    /// Validator set size exceeds maximum allowed.
    #[error(
        "invalid validator set size: {0} exceeds maximum of {}",
        MAX_VALIDATORS
    )]
    InvalidValidatorSetSize(usize),

    /// Collection size exceeds maximum allowed during deserialization.
    #[error("deserialization size limit exceeded: {actual} exceeds maximum of {limit}")]
    DeserializationSizeExceeded {
        /// Actual size from the serialized data
        actual: usize,
        /// Maximum allowed size
        limit: usize,
    },

    /// Generic error for other consensus failures.
    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_validator_set_error_display() {
        let err = ConsensusError::EmptyValidatorSet;
        assert_eq!(err.to_string(), "validator set cannot be empty");
    }

    #[test]
    fn test_invalid_config_error_display() {
        let err = ConsensusError::InvalidConfig("bad timeout".to_string());
        assert_eq!(err.to_string(), "invalid configuration: bad timeout");
    }

    #[test]
    fn test_invalid_validator_set_size_error_display() {
        let err = ConsensusError::InvalidValidatorSetSize(15_000);
        assert!(err.to_string().contains("15000"));
        assert!(err.to_string().contains("10000"));
    }

    #[test]
    fn test_deserialization_size_exceeded_error_display() {
        let err = ConsensusError::DeserializationSizeExceeded {
            actual: 50_000,
            limit: 10_000,
        };
        assert!(err.to_string().contains("50000"));
        assert!(err.to_string().contains("10000"));
    }

    #[test]
    fn test_error_equality() {
        let err1 = ConsensusError::EmptyValidatorSet;
        let err2 = ConsensusError::EmptyValidatorSet;
        assert_eq!(err1, err2);

        let err3 = ConsensusError::InvalidConfig("a".to_string());
        let err4 = ConsensusError::InvalidConfig("a".to_string());
        assert_eq!(err3, err4);

        let err5 = ConsensusError::InvalidConfig("b".to_string());
        assert_ne!(err3, err5);

        let err6 = ConsensusError::InvalidValidatorSetSize(100);
        let err7 = ConsensusError::InvalidValidatorSetSize(100);
        assert_eq!(err6, err7);

        let err8 = ConsensusError::InvalidValidatorSetSize(200);
        assert_ne!(err6, err8);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_max_validators_constant() {
        // Ensure the constant is reasonable (between 100 and 100,000)
        assert!(MAX_VALIDATORS >= 100);
        assert!(MAX_VALIDATORS <= 100_000);
    }
}
