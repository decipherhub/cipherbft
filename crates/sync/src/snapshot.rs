//! State snapshot types and management

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Snapshot creation interval in blocks
pub const SNAPSHOT_INTERVAL: u64 = 10_000;

/// State snapshot metadata
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSnapshot {
    /// Block height this snapshot represents
    pub block_number: u64,
    /// Block hash at this height
    pub block_hash: B256,
    /// State root (MPT root of all accounts)
    pub state_root: B256,
    /// Unix timestamp when snapshot was created
    pub timestamp: u64,
}

impl StateSnapshot {
    /// Create a new snapshot
    pub fn new(block_number: u64, block_hash: B256, state_root: B256, timestamp: u64) -> Self {
        Self {
            block_number,
            block_hash,
            state_root,
            timestamp,
        }
    }

    /// Check if this is a valid snapshot height
    pub fn is_valid_snapshot_height(height: u64) -> bool {
        height > 0 && height.is_multiple_of(SNAPSHOT_INTERVAL)
    }

    /// Get the nearest snapshot height at or below the given height
    pub fn nearest_snapshot_height(height: u64) -> u64 {
        (height / SNAPSHOT_INTERVAL) * SNAPSHOT_INTERVAL
    }
}

/// Snapshot agreement from peers
#[derive(Clone, Debug)]
pub struct SnapshotAgreement {
    /// The agreed snapshot
    pub snapshot: StateSnapshot,
    /// Number of peers agreeing on this snapshot
    pub peer_count: usize,
    /// Peers that provided this snapshot
    pub peers: Vec<String>,
}

impl SnapshotAgreement {
    /// Check if we have enough peers agreeing (2f+1 for f=7, so 15 of 21)
    /// For sync, we use a lower threshold since we verify proofs
    pub fn has_quorum(&self, min_peers: usize) -> bool {
        self.peer_count >= min_peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_snapshot_heights() {
        assert!(!StateSnapshot::is_valid_snapshot_height(0));
        assert!(!StateSnapshot::is_valid_snapshot_height(1));
        assert!(!StateSnapshot::is_valid_snapshot_height(9999));
        assert!(StateSnapshot::is_valid_snapshot_height(10000));
        assert!(!StateSnapshot::is_valid_snapshot_height(10001));
        assert!(StateSnapshot::is_valid_snapshot_height(20000));
    }

    #[test]
    fn test_nearest_snapshot_height() {
        assert_eq!(StateSnapshot::nearest_snapshot_height(0), 0);
        assert_eq!(StateSnapshot::nearest_snapshot_height(1), 0);
        assert_eq!(StateSnapshot::nearest_snapshot_height(9999), 0);
        assert_eq!(StateSnapshot::nearest_snapshot_height(10000), 10000);
        assert_eq!(StateSnapshot::nearest_snapshot_height(10001), 10000);
        assert_eq!(StateSnapshot::nearest_snapshot_height(19999), 10000);
        assert_eq!(StateSnapshot::nearest_snapshot_height(25000), 20000);
    }

    #[test]
    fn test_snapshot_serialization() {
        let snapshot = StateSnapshot::new(
            10000,
            B256::repeat_byte(0xab),
            B256::repeat_byte(0xcd),
            1234567890,
        );

        let encoded = bincode::serialize(&snapshot).unwrap();
        let decoded: StateSnapshot = bincode::deserialize(&encoded).unwrap();

        assert_eq!(snapshot, decoded);
    }
}
