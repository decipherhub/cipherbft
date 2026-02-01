//! Synchronization error types

use alloy_primitives::B256;
use std::time::Duration;
use thiserror::Error;

/// Result type alias for sync operations
pub type Result<T> = std::result::Result<T, SyncError>;

/// Sync error categories
#[derive(Debug, Error)]
pub enum SyncError {
    // === Network Errors ===
    /// Peer disconnected during sync
    #[error("peer {0} disconnected")]
    PeerDisconnected(String),

    /// Request timed out
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// No peers available for sync
    #[error("insufficient peers: need {needed}, have {available}")]
    InsufficientPeers {
        /// Number of peers needed
        needed: u32,
        /// Number of peers available
        available: u32,
    },

    // === Verification Errors ===
    /// Invalid merkle proof from peer
    #[error("invalid proof from peer {peer}: {reason}")]
    InvalidProof {
        /// Peer that sent the invalid proof
        peer: String,
        /// Reason for invalidity
        reason: String,
    },

    /// State root mismatch
    #[error("state root mismatch: expected {expected}, got {actual}")]
    StateRootMismatch {
        /// Expected state root
        expected: B256,
        /// Actual state root received
        actual: B256,
    },

    /// Malformed response from peer
    #[error("malformed response from peer {peer}: {reason}")]
    MalformedResponse {
        /// Peer that sent the malformed response
        peer: String,
        /// Reason for considering the response malformed
        reason: String,
    },

    // === State Errors ===
    /// No valid snapshot found
    #[error("no valid snapshot found at or before height {0}")]
    NoValidSnapshot(u64),

    /// Invalid sync state transition
    #[error("invalid state transition: {0}")]
    InvalidState(String),

    /// Snapshot height mismatch
    #[error("snapshot height mismatch: requested {requested}, got {actual}")]
    SnapshotHeightMismatch {
        /// Requested snapshot height
        requested: u64,
        /// Actual snapshot height received
        actual: u64,
    },

    // === Storage Errors ===
    /// Storage operation failed
    #[error("storage error: {0}")]
    Storage(String),

    /// Sync progress corrupted
    #[error("sync progress corrupted: {0}")]
    ProgressCorrupted(String),

    // === Configuration Errors ===
    /// Invalid configuration
    #[error("invalid configuration: {0}")]
    Config(String),
}

impl SyncError {
    /// Create an invalid proof error
    pub fn invalid_proof(peer: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidProof {
            peer: peer.into(),
            reason: reason.into(),
        }
    }

    /// Create a malformed response error
    pub fn malformed(peer: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::MalformedResponse {
            peer: peer.into(),
            reason: reason.into(),
        }
    }

    /// Check if this error indicates peer misbehavior (should ban peer)
    pub fn is_peer_misbehavior(&self) -> bool {
        matches!(
            self,
            Self::InvalidProof { .. }
                | Self::MalformedResponse { .. }
                | Self::StateRootMismatch { .. }
        )
    }

    /// Check if this error is retriable with different peer
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::PeerDisconnected(_) | Self::Timeout(_) | Self::MalformedResponse { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_disconnected_display() {
        let err = SyncError::PeerDisconnected("peer123".to_string());
        assert_eq!(err.to_string(), "peer peer123 disconnected");
    }

    #[test]
    fn test_timeout_display() {
        let err = SyncError::Timeout(Duration::from_secs(5));
        assert!(err.to_string().contains("5"));
    }

    #[test]
    fn test_insufficient_peers_display() {
        let err = SyncError::InsufficientPeers {
            needed: 3,
            available: 1,
        };
        let msg = err.to_string();
        assert!(msg.contains("3"));
        assert!(msg.contains("1"));
    }

    #[test]
    fn test_invalid_proof_constructor() {
        let err = SyncError::invalid_proof("peer1", "bad merkle path");
        match err {
            SyncError::InvalidProof { peer, reason } => {
                assert_eq!(peer, "peer1");
                assert_eq!(reason, "bad merkle path");
            }
            _ => panic!("expected InvalidProof variant"),
        }
    }

    #[test]
    fn test_malformed_constructor() {
        let err = SyncError::malformed("peer2", "missing field");
        match err {
            SyncError::MalformedResponse { peer, reason } => {
                assert_eq!(peer, "peer2");
                assert_eq!(reason, "missing field");
            }
            _ => panic!("expected MalformedResponse variant"),
        }
    }

    #[test]
    fn test_state_root_mismatch_display() {
        let expected = B256::from([1u8; 32]);
        let actual = B256::from([2u8; 32]);
        let err = SyncError::StateRootMismatch { expected, actual };
        let msg = err.to_string();
        assert!(msg.contains("state root mismatch"));
    }

    #[test]
    fn test_is_peer_misbehavior() {
        // Should be true for misbehavior errors
        assert!(SyncError::invalid_proof("p", "r").is_peer_misbehavior());
        assert!(SyncError::malformed("p", "r").is_peer_misbehavior());
        assert!(SyncError::StateRootMismatch {
            expected: B256::ZERO,
            actual: B256::ZERO,
        }
        .is_peer_misbehavior());

        // Should be false for other errors
        assert!(!SyncError::PeerDisconnected("p".to_string()).is_peer_misbehavior());
        assert!(!SyncError::Timeout(Duration::from_secs(1)).is_peer_misbehavior());
        assert!(!SyncError::NoValidSnapshot(100).is_peer_misbehavior());
        assert!(!SyncError::Storage("err".to_string()).is_peer_misbehavior());
    }

    #[test]
    fn test_is_retriable() {
        // Should be retriable
        assert!(SyncError::PeerDisconnected("p".to_string()).is_retriable());
        assert!(SyncError::Timeout(Duration::from_secs(1)).is_retriable());
        assert!(SyncError::malformed("p", "r").is_retriable());

        // Should not be retriable
        assert!(!SyncError::invalid_proof("p", "r").is_retriable());
        assert!(!SyncError::StateRootMismatch {
            expected: B256::ZERO,
            actual: B256::ZERO,
        }
        .is_retriable());
        assert!(!SyncError::NoValidSnapshot(100).is_retriable());
        assert!(!SyncError::Config("bad".to_string()).is_retriable());
    }

    #[test]
    fn test_no_valid_snapshot_display() {
        let err = SyncError::NoValidSnapshot(12345);
        assert!(err.to_string().contains("12345"));
    }

    #[test]
    fn test_snapshot_height_mismatch_display() {
        let err = SyncError::SnapshotHeightMismatch {
            requested: 100,
            actual: 50,
        };
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }
}
