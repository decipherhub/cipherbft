//! Vote types.

use crate::{Hash, Height, Round};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of vote (Prepare or Commit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Prepare phase vote.
    Prepare,
    /// Commit phase vote.
    Commit,
}

/// A vote from a validator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vote {
    /// Vote type.
    pub vote_type: VoteType,
    /// Block height.
    pub height: Height,
    /// Consensus round.
    pub round: Round,
    /// Block hash being voted for.
    pub block_hash: Hash,
    /// Validator address.
    pub validator_address: Vec<u8>,
    /// Vote signature.
    pub signature: Vec<u8>,
    /// Vote timestamp.
    pub timestamp: DateTime<Utc>,
}
