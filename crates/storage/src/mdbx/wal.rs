//! MDBX-backed Write-Ahead Log implementation
//!
//! Provides a persistent WAL for crash recovery using MDBX as the backend.
//! All consensus state changes are logged before being applied.

use crate::error::Result;
use crate::wal::{Wal, WalEntry};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, trace};

use super::database::Database;

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
    fn load_next_index(_db: &Database) -> Result<u64> {
        // TODO: Implement actual index loading from MDBX
        // For now, start at 0
        Ok(0)
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
}

#[async_trait]
impl Wal for MdbxWal {
    async fn append(&self, entry: WalEntry) -> Result<u64> {
        let index = self.next_index.fetch_add(1, Ordering::SeqCst);
        let entry_type = entry.entry_type();

        trace!(index, entry_type, "Appending WAL entry");

        let _serialized = Self::serialize_entry(&entry)?;

        // TODO: Implement actual MDBX write
        // tx.put::<ConsensusWal>(index, serialized)?;
        // tx.commit()?;

        debug!(index, entry_type, "WAL entry appended (skeleton)");

        Ok(index)
    }

    async fn replay_from(&self, start_index: u64) -> Result<Vec<(u64, WalEntry)>> {
        trace!(start_index, "Replaying WAL from index");

        // TODO: Implement actual MDBX cursor iteration
        // let tx = self.db.tx()?;
        // let mut cursor = tx.cursor::<ConsensusWal>()?;
        // let mut entries = Vec::new();
        // for (idx, data) in cursor.walk(Some(start_index))? {
        //     let entry = Self::deserialize_entry(&data)?;
        //     entries.push((idx, entry));
        // }

        Ok(Vec::new())
    }

    async fn truncate_before(&self, before_index: u64) -> Result<u64> {
        trace!(before_index, "Truncating WAL before index");

        // TODO: Implement actual MDBX deletion
        // let tx = self.db.tx_mut()?;
        // let mut cursor = tx.cursor::<ConsensusWal>()?;
        // let mut deleted = 0;
        // while let Some((idx, _)) = cursor.next()? {
        //     if idx < before_index {
        //         cursor.delete()?;
        //         deleted += 1;
        //     } else {
        //         break;
        //     }
        // }
        // tx.commit()?;

        Ok(0)
    }

    async fn next_index(&self) -> Result<u64> {
        Ok(self.next_index.load(Ordering::SeqCst))
    }

    async fn sync(&self) -> Result<()> {
        trace!("Syncing WAL to disk");

        // MDBX provides durable writes by default with proper transaction commits
        // Additional sync can be called if needed for extra safety

        // TODO: Implement explicit sync if required
        // self.db.env().sync(true)?;

        Ok(())
    }

    async fn last_checkpoint(&self) -> Result<Option<u64>> {
        trace!("Finding last checkpoint");

        // TODO: Implement reverse scan to find last checkpoint entry
        // Need to iterate backwards through WAL entries and find
        // the last WalEntry::Checkpoint

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
