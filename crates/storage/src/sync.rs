//! Sync storage for snap sync snapshots and progress tracking
//!
//! This module provides storage for state synchronization, enabling:
//! - Persistence of snapshots at regular intervals (every 10,000 blocks)
//! - Progress tracking for resumable sync operations
//!
//! # Tables
//!
//! | Table | Key | Value | Description |
//! |-------|-----|-------|-------------|
//! | SyncSnapshots | BlockNumber | StoredSyncSnapshot | State snapshots at interval blocks |
//! | SyncProgress | "current" | StoredSyncProgress | Current sync progress (single row) |

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Interval between sync snapshots (in blocks)
pub const SYNC_SNAPSHOT_INTERVAL: u64 = 10_000;

/// Stored sync snapshot metadata
///
/// Represents a point-in-time state snapshot that can be used as a
/// starting point for state synchronization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSyncSnapshot {
    /// Block height this snapshot represents
    pub block_number: u64,
    /// Block hash at this height (32 bytes)
    pub block_hash: [u8; 32],
    /// State root (MPT root of all accounts, 32 bytes)
    pub state_root: [u8; 32],
    /// Unix timestamp when snapshot was created
    pub timestamp: u64,
}

impl StoredSyncSnapshot {
    /// Create a new stored sync snapshot
    pub fn new(
        block_number: u64,
        block_hash: [u8; 32],
        state_root: [u8; 32],
        timestamp: u64,
    ) -> Self {
        Self {
            block_number,
            block_hash,
            state_root,
            timestamp,
        }
    }
}

/// Sync phase enumeration for persistence
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum StoredSyncPhase {
    /// Finding peers and selecting snapshot
    #[default]
    Discovery,
    /// Downloading accounts
    SnapSyncAccounts,
    /// Downloading storage for accounts
    SnapSyncStorage,
    /// Final state root verification
    SnapSyncVerification,
    /// Downloading and executing blocks
    BlockSync,
    /// Sync complete
    Complete,
}


/// Stored account progress for sync resumability
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAccountProgress {
    /// Last completed address (exclusive upper bound, 20 bytes)
    pub completed_up_to: Option<[u8; 20]>,
    /// Addresses that need storage downloaded
    pub accounts_needing_storage: Vec<[u8; 20]>,
    /// Total accounts downloaded
    pub total_accounts: u64,
    /// Total bytes downloaded
    pub total_bytes: u64,
}

/// Stored storage slot progress per account
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredStorageProgress {
    /// Last completed slot (exclusive upper bound, 32 bytes)
    pub completed_up_to: Option<[u8; 32]>,
    /// Total slots downloaded
    pub total_slots: u64,
}

/// Stored block sync progress
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredBlockProgress {
    /// First block needed (snapshot height + 1)
    pub start_height: u64,
    /// Last block successfully executed
    pub executed_up_to: u64,
    /// Target height to sync to
    pub target_height: u64,
}

/// Stored sync progress state
///
/// Contains all the information needed to resume a sync operation
/// after a restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSyncProgress {
    /// Current sync phase
    pub phase: StoredSyncPhase,
    /// Target snapshot being synced to
    pub target_snapshot: Option<StoredSyncSnapshot>,
    /// Account download progress
    pub account_progress: StoredAccountProgress,
    /// Storage download progress per account (address -> progress)
    pub storage_progress: Vec<([u8; 20], StoredStorageProgress)>,
    /// Block sync progress
    pub block_progress: StoredBlockProgress,
}

impl StoredSyncProgress {
    /// Create a new empty sync progress state
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset progress for fresh sync
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Trait for sync storage operations
///
/// Provides CRUD operations for sync snapshots and progress tracking.
#[async_trait]
pub trait SyncStore: Send + Sync {
    // ========================================================================
    // Snapshot Operations
    // ========================================================================

    /// Store a sync snapshot at a specific block number
    async fn put_snapshot(&self, snapshot: StoredSyncSnapshot) -> Result<()>;

    /// Get a snapshot by block number
    async fn get_snapshot(&self, block_number: u64) -> Result<Option<StoredSyncSnapshot>>;

    /// Get the latest snapshot
    async fn get_latest_snapshot(&self) -> Result<Option<StoredSyncSnapshot>>;

    /// Get snapshot at or before a specific block number
    async fn get_snapshot_at_or_before(
        &self,
        block_number: u64,
    ) -> Result<Option<StoredSyncSnapshot>>;

    /// Delete a snapshot by block number
    async fn delete_snapshot(&self, block_number: u64) -> Result<()>;

    /// List all snapshot block numbers
    async fn list_snapshot_heights(&self) -> Result<Vec<u64>>;

    // ========================================================================
    // Progress Operations
    // ========================================================================

    /// Get current sync progress (there's only one, keyed by "current")
    async fn get_progress(&self) -> Result<Option<StoredSyncProgress>>;

    /// Store sync progress (overwrites existing)
    async fn put_progress(&self, progress: StoredSyncProgress) -> Result<()>;

    /// Delete sync progress (used after successful sync completion)
    async fn delete_progress(&self) -> Result<()>;
}

/// In-memory implementation of SyncStore for testing
pub struct InMemorySyncStore {
    snapshots: parking_lot::RwLock<std::collections::BTreeMap<u64, StoredSyncSnapshot>>,
    progress: parking_lot::RwLock<Option<StoredSyncProgress>>,
}

impl InMemorySyncStore {
    /// Create a new in-memory sync store
    pub fn new() -> Self {
        Self {
            snapshots: parking_lot::RwLock::new(std::collections::BTreeMap::new()),
            progress: parking_lot::RwLock::new(None),
        }
    }
}

impl Default for InMemorySyncStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SyncStore for InMemorySyncStore {
    async fn put_snapshot(&self, snapshot: StoredSyncSnapshot) -> Result<()> {
        let block_number = snapshot.block_number;
        self.snapshots.write().insert(block_number, snapshot);
        Ok(())
    }

    async fn get_snapshot(&self, block_number: u64) -> Result<Option<StoredSyncSnapshot>> {
        Ok(self.snapshots.read().get(&block_number).cloned())
    }

    async fn get_latest_snapshot(&self) -> Result<Option<StoredSyncSnapshot>> {
        Ok(self.snapshots.read().values().last().cloned())
    }

    async fn get_snapshot_at_or_before(
        &self,
        block_number: u64,
    ) -> Result<Option<StoredSyncSnapshot>> {
        Ok(self
            .snapshots
            .read()
            .range(..=block_number)
            .next_back()
            .map(|(_, s)| s.clone()))
    }

    async fn delete_snapshot(&self, block_number: u64) -> Result<()> {
        self.snapshots.write().remove(&block_number);
        Ok(())
    }

    async fn list_snapshot_heights(&self) -> Result<Vec<u64>> {
        Ok(self.snapshots.read().keys().copied().collect())
    }

    async fn get_progress(&self) -> Result<Option<StoredSyncProgress>> {
        Ok(self.progress.read().clone())
    }

    async fn put_progress(&self, progress: StoredSyncProgress) -> Result<()> {
        *self.progress.write() = Some(progress);
        Ok(())
    }

    async fn delete_progress(&self) -> Result<()> {
        *self.progress.write() = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_snapshot_operations() {
        let store = InMemorySyncStore::new();

        // Create and store snapshots
        let snapshot1 = StoredSyncSnapshot::new(10000, [0xab; 32], [0xcd; 32], 1234567890);
        let snapshot2 = StoredSyncSnapshot::new(20000, [0xef; 32], [0x12; 32], 1234567900);

        store.put_snapshot(snapshot1.clone()).await.unwrap();
        store.put_snapshot(snapshot2.clone()).await.unwrap();

        // Get by block number
        let retrieved = store.get_snapshot(10000).await.unwrap().unwrap();
        assert_eq!(retrieved, snapshot1);

        // Get latest
        let latest = store.get_latest_snapshot().await.unwrap().unwrap();
        assert_eq!(latest, snapshot2);

        // Get at or before
        let at_or_before = store.get_snapshot_at_or_before(15000).await.unwrap().unwrap();
        assert_eq!(at_or_before, snapshot1);

        // List heights
        let heights = store.list_snapshot_heights().await.unwrap();
        assert_eq!(heights, vec![10000, 20000]);

        // Delete
        store.delete_snapshot(10000).await.unwrap();
        assert!(store.get_snapshot(10000).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_progress_operations() {
        let store = InMemorySyncStore::new();

        // Initially no progress
        assert!(store.get_progress().await.unwrap().is_none());

        // Store progress
        let mut progress = StoredSyncProgress::new();
        progress.phase = StoredSyncPhase::SnapSyncAccounts;
        progress.account_progress.total_accounts = 5000;

        store.put_progress(progress.clone()).await.unwrap();

        // Get progress
        let retrieved = store.get_progress().await.unwrap().unwrap();
        assert_eq!(retrieved.phase, StoredSyncPhase::SnapSyncAccounts);
        assert_eq!(retrieved.account_progress.total_accounts, 5000);

        // Delete progress
        store.delete_progress().await.unwrap();
        assert!(store.get_progress().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_progress_serialization() {
        let mut progress = StoredSyncProgress::new();
        progress.phase = StoredSyncPhase::SnapSyncStorage;
        progress.target_snapshot = Some(StoredSyncSnapshot::new(
            10000,
            [0xab; 32],
            [0xcd; 32],
            1234567890,
        ));
        progress.account_progress.completed_up_to = Some([0x80; 20]);
        progress.account_progress.total_accounts = 1000;
        progress.storage_progress.push((
            [0x01; 20],
            StoredStorageProgress {
                completed_up_to: Some([0xff; 32]),
                total_slots: 500,
            },
        ));

        // Serialize and deserialize
        let encoded = bincode::serialize(&progress).unwrap();
        let decoded: StoredSyncProgress = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded.phase, StoredSyncPhase::SnapSyncStorage);
        assert_eq!(decoded.account_progress.total_accounts, 1000);
        assert_eq!(decoded.storage_progress.len(), 1);
    }
}
