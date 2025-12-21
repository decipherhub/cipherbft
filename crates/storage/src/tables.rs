//! Table schema definitions for DCL storage per ADR-010
//!
//! This module defines the table keys and value types used for storing
//! DCL data. The actual storage implementation uses these types.
//!
//! # Tables
//!
//! | Table | Key | Value | Description |
//! |-------|-----|-------|-------------|
//! | Batches | Hash | Batch | Transaction batches from Workers |
//! | Cars | (ValidatorId, u64) | Car | Cars indexed by validator and position |
//! | CarsByHash | Hash | (ValidatorId, u64) | Car hash to key mapping |
//! | Attestations | Hash | AggregatedAttestation | Aggregated attestations by Car hash |
//! | PendingCuts | u64 | Cut | Pending Cuts awaiting consensus |
//! | FinalizedCuts | u64 | Cut | Consensus-finalized Cuts |

use cipherbft_types::{Hash, ValidatorId};
use serde::{Deserialize, Serialize};

/// Key for the Batches table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BatchKey {
    /// Hash of the batch
    pub hash: Hash,
}

impl BatchKey {
    /// Create a new batch key
    pub fn new(hash: Hash) -> Self {
        Self { hash }
    }
}

impl From<Hash> for BatchKey {
    fn from(hash: Hash) -> Self {
        Self::new(hash)
    }
}

/// Key for the Cars table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CarKey {
    /// Validator ID
    pub validator_id: ValidatorId,
    /// Position in the validator's lane
    pub position: u64,
}

impl CarKey {
    /// Create a new car key
    pub fn new(validator_id: ValidatorId, position: u64) -> Self {
        Self {
            validator_id,
            position,
        }
    }
}

impl From<(ValidatorId, u64)> for CarKey {
    fn from((validator_id, position): (ValidatorId, u64)) -> Self {
        Self::new(validator_id, position)
    }
}

/// Key for the CarsByHash table (secondary index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CarHashKey {
    /// Hash of the Car
    pub hash: Hash,
}

impl CarHashKey {
    /// Create a new car hash key
    pub fn new(hash: Hash) -> Self {
        Self { hash }
    }
}

impl From<Hash> for CarHashKey {
    fn from(hash: Hash) -> Self {
        Self::new(hash)
    }
}

/// Key for the Attestations table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttestationKey {
    /// Hash of the Car being attested
    pub car_hash: Hash,
}

impl AttestationKey {
    /// Create a new attestation key
    pub fn new(car_hash: Hash) -> Self {
        Self { car_hash }
    }
}

impl From<Hash> for AttestationKey {
    fn from(car_hash: Hash) -> Self {
        Self::new(car_hash)
    }
}

/// Key for the PendingCuts and FinalizedCuts tables
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CutKey {
    /// Consensus height
    pub height: u64,
}

impl CutKey {
    /// Create a new cut key
    pub fn new(height: u64) -> Self {
        Self { height }
    }
}

impl From<u64> for CutKey {
    fn from(height: u64) -> Self {
        Self::new(height)
    }
}

/// Key range for iterating over Cars by validator
#[derive(Debug, Clone, Copy)]
pub struct CarRange {
    /// Validator ID
    pub validator_id: ValidatorId,
    /// Start position (inclusive)
    pub start: u64,
    /// End position (exclusive), None for unbounded
    pub end: Option<u64>,
}

impl CarRange {
    /// Create a new car range
    pub fn new(validator_id: ValidatorId, start: u64, end: Option<u64>) -> Self {
        Self {
            validator_id,
            start,
            end,
        }
    }

    /// Create a range for all Cars from a validator
    pub fn all(validator_id: ValidatorId) -> Self {
        Self::new(validator_id, 0, None)
    }

    /// Create a range for a single Car
    pub fn single(validator_id: ValidatorId, position: u64) -> Self {
        Self::new(validator_id, position, Some(position + 1))
    }
}

/// Key range for iterating over Cuts by height
#[derive(Debug, Clone, Copy)]
pub struct CutRange {
    /// Start height (inclusive)
    pub start: u64,
    /// End height (exclusive), None for unbounded
    pub end: Option<u64>,
}

impl CutRange {
    /// Create a new cut range
    pub fn new(start: u64, end: Option<u64>) -> Self {
        Self { start, end }
    }

    /// Create a range for all Cuts
    pub fn all() -> Self {
        Self::new(0, None)
    }

    /// Create a range for a single Cut
    pub fn single(height: u64) -> Self {
        Self::new(height, Some(height + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_types::VALIDATOR_ID_SIZE;

    fn make_validator_id(id: u8) -> ValidatorId {
        let mut bytes = [0u8; VALIDATOR_ID_SIZE];
        bytes[0] = id;
        ValidatorId::from_bytes(bytes)
    }

    #[test]
    fn test_batch_key() {
        let hash = Hash::compute(b"batch");
        let key = BatchKey::new(hash);
        assert_eq!(key.hash, hash);

        let key2: BatchKey = hash.into();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_car_key() {
        let validator = make_validator_id(1);
        let key = CarKey::new(validator, 42);
        assert_eq!(key.validator_id, validator);
        assert_eq!(key.position, 42);

        let key2: CarKey = (validator, 42).into();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_car_range() {
        let validator = make_validator_id(1);
        let range = CarRange::all(validator);
        assert_eq!(range.start, 0);
        assert!(range.end.is_none());

        let single = CarRange::single(validator, 5);
        assert_eq!(single.start, 5);
        assert_eq!(single.end, Some(6));
    }

    #[test]
    fn test_cut_range() {
        let range = CutRange::all();
        assert_eq!(range.start, 0);
        assert!(range.end.is_none());

        let single = CutRange::single(100);
        assert_eq!(single.start, 100);
        assert_eq!(single.end, Some(101));
    }
}
