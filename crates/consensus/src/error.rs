//! Consensus layer error types

use thiserror::Error;

/// Errors that can occur during consensus operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// Validator set cannot be empty for consensus operations.
    #[error("validator set cannot be empty")]
    EmptyValidatorSet,

    /// Invalid configuration provided.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
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
    fn test_error_equality() {
        let err1 = ConsensusError::EmptyValidatorSet;
        let err2 = ConsensusError::EmptyValidatorSet;
        assert_eq!(err1, err2);

        let err3 = ConsensusError::InvalidConfig("a".to_string());
        let err4 = ConsensusError::InvalidConfig("a".to_string());
        assert_eq!(err3, err4);

        let err5 = ConsensusError::InvalidConfig("b".to_string());
        assert_ne!(err3, err5);
    }
}
