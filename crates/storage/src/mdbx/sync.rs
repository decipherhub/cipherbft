//! MDBX-based implementation of sync storage.
//!
//! This module provides the [`MdbxSyncStore`] implementation of [`SyncStore`] trait
//! using MDBX as the backing storage engine.

use std::sync::Arc;

use async_trait::async_trait;
use reth_db::Database;
use reth_db_api::cursor::DbCursorRO;
use reth_db_api::transaction::{DbTx, DbTxMut};

use super::database::DatabaseEnv;
use super::tables::{
    BlockNumberKey, StoredAccountProgress, StoredBlockProgress, StoredStorageProgress,
    StoredSyncPhase, StoredSyncProgressState, StoredSyncSnapshot, SyncProgress, SyncProgressKey,
    SyncSnapshots,
};
use crate::error::{Result, StorageError};
use crate::sync::{
    StoredSyncProgress as SyncStoredSyncProgress, StoredSyncSnapshot as SyncStoredSyncSnapshot,
    SyncStore,
};

/// Helper to convert database errors to storage errors.
fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// MDBX-based sync storage implementation.
///
/// This implementation uses reth-db (MDBX) for persistent storage of sync state.
pub struct MdbxSyncStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxSyncStore {
    /// Create a new MDBX sync store.
    ///
    /// # Arguments
    /// * `db` - Shared reference to the MDBX database environment
    pub fn new(db: Arc<DatabaseEnv>) -> Self {
        Self { db }
    }

    /// Convert from sync module's StoredSyncSnapshot to MDBX's StoredSyncSnapshot
    fn to_mdbx_snapshot(snapshot: &SyncStoredSyncSnapshot) -> StoredSyncSnapshot {
        StoredSyncSnapshot {
            block_number: snapshot.block_number,
            block_hash: snapshot.block_hash,
            state_root: snapshot.state_root,
            timestamp: snapshot.timestamp,
        }
    }

    /// Convert from MDBX's StoredSyncSnapshot to sync module's StoredSyncSnapshot
    fn from_mdbx_snapshot(snapshot: &StoredSyncSnapshot) -> SyncStoredSyncSnapshot {
        SyncStoredSyncSnapshot {
            block_number: snapshot.block_number,
            block_hash: snapshot.block_hash,
            state_root: snapshot.state_root,
            timestamp: snapshot.timestamp,
        }
    }

    /// Convert from sync module's StoredSyncProgress to MDBX's StoredSyncProgressState
    fn to_mdbx_progress(progress: &SyncStoredSyncProgress) -> StoredSyncProgressState {
        use crate::sync::StoredSyncPhase as SyncPhase;

        let phase = match &progress.phase {
            SyncPhase::Discovery => StoredSyncPhase::Discovery,
            SyncPhase::SnapSyncAccounts => StoredSyncPhase::SnapSyncAccounts,
            SyncPhase::SnapSyncStorage => StoredSyncPhase::SnapSyncStorage,
            SyncPhase::SnapSyncVerification => StoredSyncPhase::SnapSyncVerification,
            SyncPhase::BlockSync => StoredSyncPhase::BlockSync,
            SyncPhase::Complete => StoredSyncPhase::Complete,
        };

        let target_snapshot = progress
            .target_snapshot
            .as_ref()
            .map(Self::to_mdbx_snapshot);

        let account_progress = StoredAccountProgress {
            completed_up_to: progress.account_progress.completed_up_to,
            accounts_needing_storage: progress.account_progress.accounts_needing_storage.clone(),
            total_accounts: progress.account_progress.total_accounts,
            total_bytes: progress.account_progress.total_bytes,
        };

        let storage_progress: Vec<([u8; 20], StoredStorageProgress)> = progress
            .storage_progress
            .iter()
            .map(|(addr, prog)| {
                (
                    *addr,
                    StoredStorageProgress {
                        completed_up_to: prog.completed_up_to,
                        total_slots: prog.total_slots,
                    },
                )
            })
            .collect();

        let block_progress = StoredBlockProgress {
            start_height: progress.block_progress.start_height,
            executed_up_to: progress.block_progress.executed_up_to,
            target_height: progress.block_progress.target_height,
        };

        StoredSyncProgressState {
            phase,
            target_snapshot,
            account_progress,
            storage_progress,
            block_progress,
        }
    }

    /// Convert from MDBX's StoredSyncProgressState to sync module's StoredSyncProgress
    fn from_mdbx_progress(progress: &StoredSyncProgressState) -> SyncStoredSyncProgress {
        use crate::sync::{
            StoredAccountProgress as SyncAccountProgress, StoredBlockProgress as SyncBlockProgress,
            StoredStorageProgress as SyncStorageProgress, StoredSyncPhase as SyncPhase,
        };

        let phase = match &progress.phase {
            StoredSyncPhase::Discovery => SyncPhase::Discovery,
            StoredSyncPhase::SnapSyncAccounts => SyncPhase::SnapSyncAccounts,
            StoredSyncPhase::SnapSyncStorage => SyncPhase::SnapSyncStorage,
            StoredSyncPhase::SnapSyncVerification => SyncPhase::SnapSyncVerification,
            StoredSyncPhase::BlockSync => SyncPhase::BlockSync,
            StoredSyncPhase::Complete => SyncPhase::Complete,
        };

        let target_snapshot = progress
            .target_snapshot
            .as_ref()
            .map(Self::from_mdbx_snapshot);

        let account_progress = SyncAccountProgress {
            completed_up_to: progress.account_progress.completed_up_to,
            accounts_needing_storage: progress.account_progress.accounts_needing_storage.clone(),
            total_accounts: progress.account_progress.total_accounts,
            total_bytes: progress.account_progress.total_bytes,
        };

        let storage_progress: Vec<([u8; 20], SyncStorageProgress)> = progress
            .storage_progress
            .iter()
            .map(|(addr, prog)| {
                (
                    *addr,
                    SyncStorageProgress {
                        completed_up_to: prog.completed_up_to,
                        total_slots: prog.total_slots,
                    },
                )
            })
            .collect();

        let block_progress = SyncBlockProgress {
            start_height: progress.block_progress.start_height,
            executed_up_to: progress.block_progress.executed_up_to,
            target_height: progress.block_progress.target_height,
        };

        SyncStoredSyncProgress {
            phase,
            target_snapshot,
            account_progress,
            storage_progress,
            block_progress,
        }
    }
}

#[async_trait]
impl SyncStore for MdbxSyncStore {
    async fn put_snapshot(&self, snapshot: SyncStoredSyncSnapshot) -> Result<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey::new(snapshot.block_number);
        let stored = Self::to_mdbx_snapshot(&snapshot);

        tx.put::<SyncSnapshots>(key, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    async fn get_snapshot(&self, block_number: u64) -> Result<Option<SyncStoredSyncSnapshot>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey::new(block_number);
        let result = tx
            .get::<SyncSnapshots>(key)
            .map_err(|e| db_err(e.to_string()))?;

        Ok(result.map(|stored| Self::from_mdbx_snapshot(&stored.0)))
    }

    async fn get_latest_snapshot(&self) -> Result<Option<SyncStoredSyncSnapshot>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let mut cursor = tx
            .cursor_read::<SyncSnapshots>()
            .map_err(|e| db_err(e.to_string()))?;

        let last_entry = cursor.last().map_err(|e| db_err(e.to_string()))?;

        Ok(last_entry.map(|(_, stored)| Self::from_mdbx_snapshot(&stored.0)))
    }

    async fn get_snapshot_at_or_before(
        &self,
        block_number: u64,
    ) -> Result<Option<SyncStoredSyncSnapshot>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let mut cursor = tx
            .cursor_read::<SyncSnapshots>()
            .map_err(|e| db_err(e.to_string()))?;

        // Seek to the key and work backwards if needed
        let key = BlockNumberKey::new(block_number);
        let entry = cursor.seek(key).map_err(|e| db_err(e.to_string()))?;

        match entry {
            Some((found_key, stored)) if found_key.0 == block_number => {
                Ok(Some(Self::from_mdbx_snapshot(&stored.0)))
            }
            Some((found_key, _)) if found_key.0 > block_number => {
                // We went past, go back one
                let prev = cursor.prev().map_err(|e| db_err(e.to_string()))?;
                Ok(prev.map(|(_, stored)| Self::from_mdbx_snapshot(&stored.0)))
            }
            Some((_, stored)) => Ok(Some(Self::from_mdbx_snapshot(&stored.0))),
            None => {
                // Seek went past end, get last entry
                let last = cursor.last().map_err(|e| db_err(e.to_string()))?;
                match last {
                    Some((k, stored)) if k.0 <= block_number => {
                        Ok(Some(Self::from_mdbx_snapshot(&stored.0)))
                    }
                    _ => Ok(None),
                }
            }
        }
    }

    async fn delete_snapshot(&self, block_number: u64) -> Result<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey::new(block_number);
        tx.delete::<SyncSnapshots>(key, None)
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    async fn list_snapshot_heights(&self) -> Result<Vec<u64>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let mut cursor = tx
            .cursor_read::<SyncSnapshots>()
            .map_err(|e| db_err(e.to_string()))?;

        let mut heights = Vec::new();
        let mut entry = cursor.first().map_err(|e| db_err(e.to_string()))?;

        while let Some((key, _)) = entry {
            heights.push(key.0);
            entry = cursor.next().map_err(|e| db_err(e.to_string()))?;
        }

        Ok(heights)
    }

    async fn get_progress(&self) -> Result<Option<SyncStoredSyncProgress>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let result = tx
            .get::<SyncProgress>(SyncProgressKey)
            .map_err(|e| db_err(e.to_string()))?;

        Ok(result.map(|stored| Self::from_mdbx_progress(&stored.0)))
    }

    async fn put_progress(&self, progress: SyncStoredSyncProgress) -> Result<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let stored = Self::to_mdbx_progress(&progress);
        tx.put::<SyncProgress>(SyncProgressKey, stored.into())
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }

    async fn delete_progress(&self) -> Result<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        tx.delete::<SyncProgress>(SyncProgressKey, None)
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdbx::Database;
    use crate::sync::{StoredSyncPhase, StoredSyncProgress, StoredSyncSnapshot};

    fn create_test_db() -> (Arc<DatabaseEnv>, tempfile::TempDir) {
        let (db, temp_dir) = Database::open_temp().unwrap();
        (Arc::clone(db.env()), temp_dir)
    }

    #[tokio::test]
    async fn test_snapshot_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxSyncStore::new(db);

        // Create and store snapshots
        let snapshot1 = StoredSyncSnapshot::new(10000, [0xab; 32], [0xcd; 32], 1234567890);
        let snapshot2 = StoredSyncSnapshot::new(20000, [0xef; 32], [0x12; 32], 1234567900);

        store.put_snapshot(snapshot1.clone()).await.unwrap();
        store.put_snapshot(snapshot2.clone()).await.unwrap();

        // Get by block number
        let retrieved = store.get_snapshot(10000).await.unwrap().unwrap();
        assert_eq!(retrieved.block_number, snapshot1.block_number);
        assert_eq!(retrieved.block_hash, snapshot1.block_hash);

        // Get latest
        let latest = store.get_latest_snapshot().await.unwrap().unwrap();
        assert_eq!(latest.block_number, snapshot2.block_number);

        // Get at or before
        let at_or_before = store
            .get_snapshot_at_or_before(15000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(at_or_before.block_number, snapshot1.block_number);

        // List heights
        let heights = store.list_snapshot_heights().await.unwrap();
        assert_eq!(heights, vec![10000, 20000]);

        // Delete
        store.delete_snapshot(10000).await.unwrap();
        assert!(store.get_snapshot(10000).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_progress_operations() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxSyncStore::new(db);

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
    async fn test_snapshot_at_or_before() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxSyncStore::new(db);

        // Add snapshots at 10k, 20k, 30k
        for height in [10000u64, 20000, 30000] {
            let snapshot = StoredSyncSnapshot::new(height, [height as u8; 32], [0; 32], height);
            store.put_snapshot(snapshot).await.unwrap();
        }

        // Query at exact boundaries
        let at_10k = store
            .get_snapshot_at_or_before(10000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(at_10k.block_number, 10000);

        // Query between snapshots
        let at_15k = store
            .get_snapshot_at_or_before(15000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(at_15k.block_number, 10000);

        let at_25k = store
            .get_snapshot_at_or_before(25000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(at_25k.block_number, 20000);

        // Query past all snapshots
        let at_40k = store
            .get_snapshot_at_or_before(40000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(at_40k.block_number, 30000);

        // Query before first snapshot
        let at_5k = store.get_snapshot_at_or_before(5000).await.unwrap();
        assert!(at_5k.is_none());
    }
}
