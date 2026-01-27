//! MDBX backend for Persistent State Store
//!
//! Provides durable persistence for state snapshots and deltas using MDBX.

use crate::error::{Result, StorageError};
use crate::persistent_state::{StateDelta, StatePersistence, StateSnapshot, VersionedState};
use async_trait::async_trait;
use reth_db_api::cursor::DbCursorRO;
use reth_db_api::transaction::{DbTx, DbTxMut};
use std::marker::PhantomData;
use std::sync::Arc;
use tracing::{debug, trace};

use super::database::Database;
use super::tables::{
    BincodeValue, HeightKey, StateDeltas, StateSnapshots, StoredStateDelta, StoredStateSnapshot,
};

// ============================================================================
// MDBX StatePersistence Implementation
// ============================================================================

/// MDBX-backed implementation of StatePersistence trait
pub struct MdbxStatePersistence<S: VersionedState> {
    /// The underlying database
    db: Arc<Database>,
    /// Phantom data for state type
    _phantom: PhantomData<S>,
}

impl<S: VersionedState> MdbxStatePersistence<S> {
    /// Create a new MDBX state persistence backend
    pub fn new(db: Arc<Database>) -> Self {
        debug!("Initialized MDBX state persistence");
        Self {
            db,
            _phantom: PhantomData,
        }
    }

    /// Get the underlying database
    pub fn db(&self) -> &Arc<Database> {
        &self.db
    }

    /// Serialize a state for storage
    fn serialize_state(state: &S) -> Result<Vec<u8>> {
        bincode::serialize(state)
            .map_err(|e| StorageError::Serialization(format!("Failed to serialize state: {e}")))
    }

    /// Deserialize a state from storage
    fn deserialize_state(data: &[u8]) -> Result<S> {
        bincode::deserialize(data)
            .map_err(|e| StorageError::Deserialization(format!("Failed to deserialize state: {e}")))
    }

    /// Serialize a delta for storage
    fn serialize_delta(delta: &StateDelta) -> Result<Vec<u8>> {
        bincode::serialize(delta)
            .map_err(|e| StorageError::Serialization(format!("Failed to serialize delta: {e}")))
    }

    /// Deserialize a delta from storage
    fn deserialize_delta(data: &[u8]) -> Result<StateDelta> {
        bincode::deserialize(data)
            .map_err(|e| StorageError::Deserialization(format!("Failed to deserialize delta: {e}")))
    }
}

#[async_trait]
impl<S: VersionedState> StatePersistence<S> for MdbxStatePersistence<S> {
    async fn save_snapshot(&self, snapshot: &StateSnapshot<S>) -> Result<()> {
        let version = snapshot.version;
        trace!(version, "Saving state snapshot");

        let state_bytes = Self::serialize_state(snapshot.state())?;

        let stored = StoredStateSnapshot {
            state_bytes,
            version: snapshot.version,
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            persisted: snapshot.persisted,
        };

        let tx = self.db.tx_mut()?;
        tx.put::<StateSnapshots>(HeightKey::new(version), BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to save snapshot: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit snapshot: {e}")))?;

        debug!(version, "Saved state snapshot");
        Ok(())
    }

    async fn load_latest_snapshot(&self) -> Result<Option<StateSnapshot<S>>> {
        trace!("Loading latest state snapshot");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<StateSnapshots>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        match cursor
            .last()
            .map_err(|e| StorageError::Database(format!("Cursor last failed: {e}")))?
        {
            Some((key, value)) => {
                let stored = value.0;
                let state: S = Self::deserialize_state(&stored.state_bytes)?;
                let snapshot = StateSnapshot {
                    state: Arc::new(state),
                    version: stored.version,
                    timestamp: std::time::Instant::now(), // Best effort
                    persisted: stored.persisted,
                };
                debug!(version = key.0, "Loaded latest snapshot");
                Ok(Some(snapshot))
            }
            None => {
                debug!("No snapshots found");
                Ok(None)
            }
        }
    }

    async fn load_snapshot(&self, version: u64) -> Result<Option<StateSnapshot<S>>> {
        trace!(version, "Loading state snapshot");

        let tx = self.db.tx()?;
        match tx
            .get::<StateSnapshots>(HeightKey::new(version))
            .map_err(|e| StorageError::Database(format!("Failed to get snapshot: {e}")))?
        {
            Some(value) => {
                let stored = value.0;
                let state: S = Self::deserialize_state(&stored.state_bytes)?;
                let snapshot = StateSnapshot {
                    state: Arc::new(state),
                    version: stored.version,
                    timestamp: std::time::Instant::now(),
                    persisted: stored.persisted,
                };
                debug!(version, "Loaded snapshot");
                Ok(Some(snapshot))
            }
            None => {
                debug!(version, "Snapshot not found");
                Ok(None)
            }
        }
    }

    async fn save_delta(&self, delta: &StateDelta) -> Result<()> {
        let from_version = delta.from_version;
        let to_version = delta.to_version;
        trace!(from_version, to_version, "Saving state delta");

        let delta_bytes = Self::serialize_delta(delta)?;

        let stored = StoredStateDelta {
            from_version,
            to_version,
            data: delta_bytes,
            created_at: delta.created_at,
        };

        let tx = self.db.tx_mut()?;
        tx.put::<StateDeltas>(HeightKey::new(from_version), BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to save delta: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit delta: {e}")))?;

        debug!(from_version, to_version, "Saved state delta");
        Ok(())
    }

    async fn load_deltas_since(&self, version: u64) -> Result<Vec<StateDelta>> {
        trace!(version, "Loading deltas since version");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<StateDeltas>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        let mut deltas = Vec::new();

        // Seek to the starting version
        let mut current = cursor
            .seek(HeightKey::new(version))
            .map_err(|e| StorageError::Database(format!("Cursor seek failed: {e}")))?;

        while let Some((_key, value)) = current {
            let stored = value.0;
            let delta = Self::deserialize_delta(&stored.data)?;
            deltas.push(delta);

            current = cursor
                .next()
                .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
        }

        debug!(version, count = deltas.len(), "Loaded deltas");
        Ok(deltas)
    }

    async fn clear_deltas_before(&self, version: u64) -> Result<u64> {
        use reth_db_api::cursor::DbCursorRW;

        trace!(version, "Clearing deltas before version");

        let tx = self.db.tx_mut()?;
        let mut cursor = tx
            .cursor_write::<StateDeltas>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        let mut deleted = 0u64;

        // Start from the beginning
        let mut current = cursor
            .first()
            .map_err(|e| StorageError::Database(format!("Cursor first failed: {e}")))?;

        while let Some((key, _)) = current {
            if key.0 >= version {
                break;
            }

            cursor
                .delete_current()
                .map_err(|e| StorageError::Database(format!("Failed to delete: {e}")))?;
            deleted += 1;

            current = cursor
                .next()
                .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
        }

        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit: {e}")))?;

        debug!(version, deleted, "Cleared deltas");
        Ok(deleted)
    }

    async fn sync(&self) -> Result<()> {
        trace!("Syncing state persistence to disk");
        // MDBX commits are already durable when transaction commits
        // No additional sync needed
        Ok(())
    }
}

// ============================================================================
// Builder for easy construction
// ============================================================================

/// Builder for creating an MDBX-backed persistent state store
pub struct MdbxPersistentStateBuilder<S: VersionedState> {
    db: Arc<Database>,
    _phantom: PhantomData<S>,
}

impl<S: VersionedState> MdbxPersistentStateBuilder<S> {
    /// Create a new builder
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            _phantom: PhantomData,
        }
    }

    /// Build the state persistence backend
    pub fn build(self) -> MdbxStatePersistence<S> {
        MdbxStatePersistence::new(self.db)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use crate::persistent_state::StateChange;
    use serde::{Deserialize, Serialize};

    /// Simple test state for integration tests
    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    struct TestState {
        value: u64,
        version: u64,
    }

    impl VersionedState for TestState {
        fn version(&self) -> u64 {
            self.version
        }

        fn set_version(&mut self, version: u64) {
            self.version = version;
        }

        fn diff(&self, other: &Self) -> StateDelta {
            let mut delta = StateDelta::new(other.version, self.version);

            if self.value != other.value {
                delta.changes.push(StateChange::FieldUpdate {
                    path: "value".to_string(),
                    old_value: other.value.to_le_bytes().to_vec(),
                    new_value: self.value.to_le_bytes().to_vec(),
                });
            }

            delta.size_bytes = delta
                .changes
                .iter()
                .map(|c| match c {
                    StateChange::FieldUpdate {
                        old_value,
                        new_value,
                        ..
                    } => old_value.len() + new_value.len(),
                    _ => 0,
                })
                .sum();

            delta
        }

        fn apply_delta(&mut self, delta: &StateDelta) -> Result<()> {
            for change in &delta.changes {
                match change {
                    StateChange::FieldUpdate {
                        path, new_value, ..
                    } => {
                        if path == "value" && new_value.len() >= 8 {
                            self.value =
                                u64::from_le_bytes(new_value[..8].try_into().expect("checked len"));
                        }
                    }
                    _ => {}
                }
            }
            self.version = delta.to_version;
            Ok(())
        }

        fn validate(&self) -> Result<()> {
            Ok(())
        }
    }

    fn create_test_db() -> (Arc<Database>, tempfile::TempDir) {
        let (db, temp_dir) = Database::open_temp().expect("failed to open temp db");
        (Arc::new(db), temp_dir)
    }

    #[test]
    fn test_stored_delta_serialization() {
        let stored = StoredStateDelta {
            from_version: 1,
            to_version: 2,
            data: vec![1, 2, 3, 4],
            created_at: 12345,
        };

        let serialized = bincode::serialize(&stored).expect("serialization failed");
        let deserialized: StoredStateDelta =
            bincode::deserialize(&serialized).expect("deserialization failed");

        assert_eq!(deserialized.from_version, 1);
        assert_eq!(deserialized.to_version, 2);
        assert_eq!(deserialized.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_stored_snapshot_serialization() {
        let stored = StoredStateSnapshot {
            state_bytes: vec![1, 2, 3, 4, 5],
            version: 100,
            timestamp_secs: 12345,
            persisted: true,
        };

        let serialized = bincode::serialize(&stored).expect("serialization failed");
        let deserialized: StoredStateSnapshot =
            bincode::deserialize(&serialized).expect("deserialization failed");

        assert_eq!(deserialized.version, 100);
        assert_eq!(deserialized.state_bytes, vec![1, 2, 3, 4, 5]);
        assert!(deserialized.persisted);
    }

    #[tokio::test]
    async fn test_mdbx_save_and_load_snapshot() {
        let (db, _temp_dir) = create_test_db();
        let persistence: MdbxStatePersistence<TestState> = MdbxStatePersistence::new(db);

        // Create a snapshot
        let state = TestState {
            value: 42,
            version: 1,
        };
        let snapshot = StateSnapshot::new(state);

        // Save it
        persistence
            .save_snapshot(&snapshot)
            .await
            .expect("save failed");

        // Load it back
        let loaded = persistence
            .load_latest_snapshot()
            .await
            .expect("load failed");
        assert!(loaded.is_some());

        let loaded = loaded.unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.state.value, 42);
    }

    #[tokio::test]
    async fn test_mdbx_load_specific_snapshot() {
        let (db, _temp_dir) = create_test_db();
        let persistence: MdbxStatePersistence<TestState> = MdbxStatePersistence::new(db);

        // Create and save multiple snapshots
        for v in 1..=5 {
            let state = TestState {
                value: v * 10,
                version: v,
            };
            let snapshot = StateSnapshot::new(state);
            persistence
                .save_snapshot(&snapshot)
                .await
                .expect("save failed");
        }

        // Load specific version
        let loaded = persistence
            .load_snapshot(3)
            .await
            .expect("load failed")
            .expect("snapshot not found");
        assert_eq!(loaded.version, 3);
        assert_eq!(loaded.state.value, 30);

        // Load latest (should be version 5)
        let latest = persistence
            .load_latest_snapshot()
            .await
            .expect("load failed")
            .expect("no snapshot found");
        assert_eq!(latest.version, 5);
        assert_eq!(latest.state.value, 50);
    }

    #[tokio::test]
    async fn test_mdbx_save_and_load_deltas() {
        let (db, _temp_dir) = create_test_db();
        let persistence: MdbxStatePersistence<TestState> = MdbxStatePersistence::new(db);

        // Create and save deltas
        for v in 1..=3 {
            let mut delta = StateDelta::new(v, v + 1);
            delta.changes.push(StateChange::FieldUpdate {
                path: "value".to_string(),
                old_value: (v * 10).to_le_bytes().to_vec(),
                new_value: ((v + 1) * 10).to_le_bytes().to_vec(),
            });
            persistence.save_delta(&delta).await.expect("save failed");
        }

        // Load all deltas since version 1
        let deltas = persistence
            .load_deltas_since(1)
            .await
            .expect("load failed");
        assert_eq!(deltas.len(), 3);
        assert_eq!(deltas[0].from_version, 1);
        assert_eq!(deltas[0].to_version, 2);
        assert_eq!(deltas[2].from_version, 3);
        assert_eq!(deltas[2].to_version, 4);

        // Load deltas since version 2 (should get 2)
        let deltas = persistence
            .load_deltas_since(2)
            .await
            .expect("load failed");
        assert_eq!(deltas.len(), 2);
    }

    #[tokio::test]
    async fn test_mdbx_clear_deltas_before() {
        let (db, _temp_dir) = create_test_db();
        let persistence: MdbxStatePersistence<TestState> = MdbxStatePersistence::new(db);

        // Create and save deltas
        for v in 1..=5 {
            let mut delta = StateDelta::new(v, v + 1);
            delta.changes.push(StateChange::FieldUpdate {
                path: "counter".to_string(),
                old_value: vec![],
                new_value: vec![v as u8],
            });
            persistence.save_delta(&delta).await.expect("save failed");
        }

        // Clear deltas before version 3
        let cleared = persistence
            .clear_deltas_before(3)
            .await
            .expect("clear failed");
        assert_eq!(cleared, 2); // Deltas 1 and 2 should be cleared

        // Verify remaining deltas
        let remaining = persistence
            .load_deltas_since(1)
            .await
            .expect("load failed");
        assert_eq!(remaining.len(), 3); // 3, 4, 5
        assert_eq!(remaining[0].from_version, 3);
    }

    #[tokio::test]
    async fn test_mdbx_sync() {
        let (db, _temp_dir) = create_test_db();
        let persistence: MdbxStatePersistence<TestState> = MdbxStatePersistence::new(db);

        // Save some data
        let state = TestState {
            value: 100,
            version: 1,
        };
        let snapshot = StateSnapshot::new(state);
        persistence
            .save_snapshot(&snapshot)
            .await
            .expect("save failed");

        // Sync should not fail
        persistence.sync().await.expect("sync failed");
    }

    #[tokio::test]
    async fn test_mdbx_empty_load() {
        let (db, _temp_dir) = create_test_db();
        let persistence: MdbxStatePersistence<TestState> = MdbxStatePersistence::new(db);

        // Loading from empty database should return None
        let snapshot = persistence
            .load_latest_snapshot()
            .await
            .expect("load failed");
        assert!(snapshot.is_none());

        let deltas = persistence
            .load_deltas_since(0)
            .await
            .expect("load failed");
        assert!(deltas.is_empty());
    }
}
