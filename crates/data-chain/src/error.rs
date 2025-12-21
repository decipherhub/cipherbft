//! DCL error types

use cipherbft_types::{Hash, ValidatorId};
use thiserror::Error;

/// DCL errors
#[derive(Debug, Error, Clone)]
pub enum DclError {
    /// Invalid Car signature
    #[error("invalid Car signature from validator {validator}")]
    InvalidCarSignature { validator: ValidatorId },

    /// Invalid attestation signature
    #[error("invalid attestation signature from validator {attester}")]
    InvalidAttestationSignature { attester: ValidatorId },

    /// Position gap detected (expected sequential positions)
    #[error("position gap for validator {validator}: expected {expected}, got {actual}")]
    PositionGap {
        validator: ValidatorId,
        expected: u64,
        actual: u64,
    },

    /// Equivocation detected (same position with different content)
    #[error("equivocation detected: validator {validator} position {position} has multiple Cars")]
    Equivocation {
        validator: ValidatorId,
        position: u64,
    },

    /// Parent hash mismatch
    #[error("parent hash mismatch for validator {validator} position {position}")]
    ParentHashMismatch {
        validator: ValidatorId,
        position: u64,
    },

    /// Missing parent Car
    #[error("missing parent Car for validator {validator} position {position}")]
    MissingParentCar {
        validator: ValidatorId,
        position: u64,
    },

    /// Missing batch data
    #[error("missing batch: {digest}")]
    MissingBatch { digest: Hash },

    /// Cut monotonicity violation
    #[error("Cut monotonicity violation: validator {validator} position went from {old} to {new}")]
    MonotonicityViolation {
        validator: ValidatorId,
        old: u64,
        new: u64,
    },

    /// Anti-censorship rule violation
    #[error(
        "anti-censorship violation: {excluded} validators excluded (max allowed: {max_allowed})"
    )]
    AntiCensorshipViolation { excluded: usize, max_allowed: usize },

    /// Too many consecutive empty Cars
    #[error("too many consecutive empty Cars from validator {validator}: {count} (max: {max})")]
    TooManyEmptyCars {
        validator: ValidatorId,
        count: u32,
        max: u32,
    },

    /// Attestation threshold not met
    #[error("attestation threshold not met: got {got}, need {threshold}")]
    ThresholdNotMet { got: usize, threshold: usize },

    /// Unknown validator
    #[error("unknown validator: {validator}")]
    UnknownValidator { validator: ValidatorId },

    /// Batch digests not sorted
    #[error("batch digests not sorted by worker_id in Car from validator {validator}")]
    UnsortedBatchDigests { validator: ValidatorId },

    /// Invalid Car for attestation (car not found)
    #[error("cannot attest to unknown Car: {car_hash}")]
    UnknownCar { car_hash: Hash },

    /// Duplicate attestation
    #[error("duplicate attestation from {attester} for Car {car_hash}")]
    DuplicateAttestation {
        attester: ValidatorId,
        car_hash: Hash,
    },

    /// Channel send error
    #[error("channel send error: {0}")]
    ChannelSend(String),

    /// Channel receive error
    #[error("channel receive error: {0}")]
    ChannelRecv(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Storage error
    #[error("storage error: {0}")]
    Storage(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Timeout error
    #[error("timeout: {0}")]
    Timeout(String),
}

impl DclError {
    /// Check if this error indicates Byzantine behavior
    pub fn is_byzantine(&self) -> bool {
        matches!(
            self,
            DclError::InvalidCarSignature { .. }
                | DclError::InvalidAttestationSignature { .. }
                | DclError::Equivocation { .. }
                | DclError::ParentHashMismatch { .. }
        )
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DclError::MissingBatch { .. }
                | DclError::MissingParentCar { .. }
                | DclError::ChannelSend(_)
                | DclError::ChannelRecv(_)
                | DclError::Timeout(_)
        )
    }
}
