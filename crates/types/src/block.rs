//! Block types.

use crate::{Hash, Height};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A blockchain block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// Block data.
    pub data: BlockData,
}

/// Block header containing metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height.
    pub height: Height,
    /// Block hash.
    pub hash: Hash,
    /// Block timestamp.
    pub timestamp: DateTime<Utc>,
    /// Proposer address.
    pub proposer: Vec<u8>,
    /// Application state hash.
    pub app_hash: Hash,
}

/// Block data containing transactions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockData {
    /// Transactions in this block.
    pub transactions: Vec<Vec<u8>>,
}
