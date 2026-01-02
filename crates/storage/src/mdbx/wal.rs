//! MDBX-backed Write-Ahead Log implementation
//!
//! Provides a persistent WAL for crash recovery using MDBX as the backend.
//! All consensus state changes are logged before being applied.

use crate::error::{Result, StorageError};
use crate::wal::{Wal, WalEntry};
use async_trait::async_trait;
use reth_db_api::cursor::DbCursorRO;
use reth_db_api::transaction::DbTx;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, trace};

use super::database::Database;
use super::tables::{ConsensusWal as ConsensusWalTable, HeightKey, StoredWalEntry};

/// MDBX-backed WAL implementation
///
/// Stores WAL entries persistently using MDBX, ensuring crash recovery.
pub struct MdbxWal {
    /// The underlying database
    db: Arc<Database>,
    /// Next entry index (cached for performance)
    next_index: AtomicU64,
}

impl MdbxWal {
    /// Create a new MDBX WAL
    pub fn new(db: Arc<Database>) -> Result<Self> {
        // Load the next index from the database
        let next_index = Self::load_next_index(&db)?;

        debug!(next_index, "Initialized MDBX WAL");

        Ok(Self {
            db,
            next_index: AtomicU64::new(next_index),
        })
    }

    /// Load the next WAL index from database
    fn load_next_index(db: &Database) -> Result<u64> {
        let tx = db.tx()?;
        let mut cursor = tx
            .cursor_read::<ConsensusWalTable>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        // Find the last entry to determine next index
        match cursor
            .last()
            .map_err(|e| StorageError::Database(format!("Cursor last failed: {e}")))?
        {
            Some((key, _)) => Ok(key.0 + 1),
            None => Ok(0),
        }
    }

    /// Get the underlying database
    pub fn db(&self) -> &Arc<Database> {
        &self.db
    }

    /// Serialize a WAL entry for storage
    #[allow(dead_code)]
    fn serialize_entry(entry: &WalEntry) -> Result<Vec<u8>> {
        bincode::serialize(entry).map_err(|e| {
            crate::error::StorageError::Serialization(format!("Failed to serialize WAL entry: {e}"))
        })
    }

    /// Deserialize a WAL entry from storage
    #[allow(dead_code)]
    fn deserialize_entry(data: &[u8]) -> Result<WalEntry> {
        bincode::deserialize(data).map_err(|e| {
            crate::error::StorageError::Deserialization(format!(
                "Failed to deserialize WAL entry: {e}"
            ))
        })
    }

    /// Get entry type tag for storage
    fn entry_type_tag(entry: &WalEntry) -> u8 {
        match entry {
            WalEntry::BatchReceived(_) => 0,
            WalEntry::CarCreated(_) => 1,
            WalEntry::CarReceived(_) => 2,
            WalEntry::AttestationAggregated(_) => 3,
            WalEntry::CutProposed(_) => 4,
            WalEntry::CutFinalized { .. } => 5,
            WalEntry::Checkpoint { .. } => 6,
            WalEntry::PipelineStageChanged { .. } => 7,
            WalEntry::NextHeightAttestation { .. } => 8,
            WalEntry::PreservedAttestedCars { .. } => 9,
        }
    }
}

#[async_trait]
impl Wal for MdbxWal {
    async fn append(&self, entry: WalEntry) -> Result<u64> {
        use super::tables::BincodeValue;
        use reth_db_api::transaction::DbTxMut;

        let index = self.next_index.fetch_add(1, Ordering::SeqCst);
        let entry_type = entry.entry_type();

        trace!(index, entry_type, "Appending WAL entry");

        let serialized = Self::serialize_entry(&entry)?;
        let stored = StoredWalEntry {
            entry_type: Self::entry_type_tag(&entry),
            data: serialized,
        };

        let tx = self.db.tx_mut()?;
        tx.put::<ConsensusWalTable>(HeightKey::new(index), BincodeValue(stored))
            .map_err(|e| StorageError::Database(format!("Failed to put WAL entry: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Database(format!("Failed to commit WAL entry: {e}")))?;

        debug!(index, entry_type, "WAL entry appended");

        Ok(index)
    }

    async fn replay_from(&self, start_index: u64) -> Result<Vec<(u64, WalEntry)>> {
        trace!(start_index, "Replaying WAL from index");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<ConsensusWalTable>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        let mut entries = Vec::new();

        // Seek to start index
        let mut current = cursor
            .seek(HeightKey::new(start_index))
            .map_err(|e| StorageError::Database(format!("Cursor seek failed: {e}")))?;

        while let Some((key, value)) = current {
            let entry = Self::deserialize_entry(&value.0.data)?;
            entries.push((key.0, entry));

            current = cursor
                .next()
                .map_err(|e| StorageError::Database(format!("Cursor next failed: {e}")))?;
        }

        debug!(start_index, count = entries.len(), "WAL replay completed");

        Ok(entries)
    }

    async fn truncate_before(&self, before_index: u64) -> Result<u64> {
        use reth_db_api::cursor::DbCursorRW;
        use reth_db_api::transaction::DbTxMut;

        trace!(before_index, "Truncating WAL before index");

        let tx = self.db.tx_mut()?;
        let mut cursor = tx
            .cursor_write::<ConsensusWalTable>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        let mut deleted = 0u64;

        // Start from the beginning
        let mut current = cursor
            .first()
            .map_err(|e| StorageError::Database(format!("Cursor first failed: {e}")))?;

        while let Some((key, _)) = current {
            if key.0 >= before_index {
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
            .map_err(|e| StorageError::Database(format!("Failed to commit truncate: {e}")))?;

        debug!(before_index, deleted, "WAL truncation completed");

        Ok(deleted)
    }

    async fn next_index(&self) -> Result<u64> {
        Ok(self.next_index.load(Ordering::SeqCst))
    }

    async fn sync(&self) -> Result<()> {
        trace!("Syncing WAL to disk");

        // MDBX provides durable writes by default with proper transaction commits
        // The MDBX_SAFE_NOSYNC mode is not used, so writes are already durable
        // No additional sync needed as commits are already synchronous

        Ok(())
    }

    async fn last_checkpoint(&self) -> Result<Option<u64>> {
        trace!("Finding last checkpoint");

        let tx = self.db.tx()?;
        let mut cursor = tx
            .cursor_read::<ConsensusWalTable>()
            .map_err(|e| StorageError::Database(format!("Failed to create cursor: {e}")))?;

        // Iterate backwards to find the last checkpoint
        let mut current = cursor
            .last()
            .map_err(|e| StorageError::Database(format!("Cursor last failed: {e}")))?;

        while let Some((key, value)) = current {
            // Check if this is a checkpoint entry (entry_type == 6)
            if value.0.entry_type == 6 {
                return Ok(Some(key.0));
            }

            current = cursor
                .prev()
                .map_err(|e| StorageError::Database(format!("Cursor prev failed: {e}")))?;
        }

        Ok(None)
    }

    async fn checkpoint(&self, height: u64) -> Result<u64> {
        let entry_count = self.next_index().await?;

        trace!(height, entry_count, "Creating checkpoint");

        let entry = WalEntry::Checkpoint {
            height,
            entry_count,
        };

        self.append(entry).await
    }
}

/// WAL entry index key
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WalIndexKey(pub u64);

impl reth_db_api::table::Encode for WalIndexKey {
    type Encoded = [u8; 8];

    fn encode(self) -> Self::Encoded {
        self.0.to_be_bytes()
    }
}

impl reth_db_api::table::Decode for WalIndexKey {
    fn decode(value: &[u8]) -> std::result::Result<Self, reth_db_api::DatabaseError> {
        if value.len() < 8 {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        Ok(Self(u64::from_be_bytes(value[..8].try_into().unwrap())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_db_api::table::Decode;

    #[test]
    fn test_wal_entry_serialization() {
        let entry = WalEntry::Checkpoint {
            height: 100,
            entry_count: 50,
        };

        let serialized = MdbxWal::serialize_entry(&entry).unwrap();
        let deserialized = MdbxWal::deserialize_entry(&serialized).unwrap();

        match deserialized {
            WalEntry::Checkpoint {
                height,
                entry_count,
            } => {
                assert_eq!(height, 100);
                assert_eq!(entry_count, 50);
            }
            _ => panic!("Wrong entry type"),
        }
    }

    #[test]
    fn test_wal_index_key_encode_decode() {
        let key = WalIndexKey(12345);
        let encoded = reth_db_api::table::Encode::encode(key);
        let decoded = WalIndexKey::decode(&encoded).unwrap();
        assert_eq!(key.0, decoded.0);
    }
}
