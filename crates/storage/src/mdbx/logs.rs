//! MDBX-based implementation of LogStore.
//!
//! This module provides the [`MdbxLogStore`] implementation of [`LogStore`] trait
//! using MDBX as the backing storage engine for transaction log/event persistence.

use std::sync::Arc;

use async_trait::async_trait;
use reth_db::Database;
use reth_db_api::cursor::DbCursorRO;
use reth_db_api::transaction::{DbTx, DbTxMut};

use super::database::DatabaseEnv;
use super::tables::{
    AddressLogKey, BincodeValue, BlockBlooms, BlockNumberKey, BlocksByHash, LogKey, Logs,
    LogsByAddress, StoredBloom, StoredLogEntry, UnitKey,
};
use crate::error::StorageError;
use crate::logs::{LogFilter, LogStore, LogStoreResult, StoredLog};

/// Helper to convert database errors to storage errors.
fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// MDBX-based log storage implementation.
///
/// This implementation uses reth-db (MDBX) for persistent storage of transaction
/// logs/events. Logs are stored in multiple tables for efficient querying:
///
/// - `Logs`: Primary storage indexed by (block_number, log_index)
/// - `LogsByAddress`: Secondary index for address-filtered queries
/// - `BlockBlooms`: Bloom filters for fast negative lookups
///
/// # Thread Safety
///
/// This type is thread-safe and can be shared across threads using `Arc`.
/// The underlying MDBX database handles concurrent access.
pub struct MdbxLogStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxLogStore {
    /// Create a new MDBX log store.
    ///
    /// # Arguments
    /// * `db` - Shared reference to the MDBX database environment
    pub fn new(db: Arc<DatabaseEnv>) -> Self {
        Self { db }
    }

    /// Convert a StoredLog to StoredLogEntry for persistence.
    fn log_to_entry(log: &StoredLog) -> StoredLogEntry {
        StoredLogEntry {
            address: log.address,
            topics: log.topics.clone(),
            data: log.data.clone(),
            block_hash: log.block_hash,
            transaction_hash: log.transaction_hash,
            transaction_index: log.transaction_index,
            removed: log.removed,
        }
    }

    /// Convert a StoredLogEntry back to a StoredLog with block context.
    fn entry_to_log(entry: StoredLogEntry, block_number: u64, log_index: u32) -> StoredLog {
        StoredLog {
            address: entry.address,
            topics: entry.topics,
            data: entry.data,
            block_number,
            block_hash: entry.block_hash,
            transaction_hash: entry.transaction_hash,
            transaction_index: entry.transaction_index,
            log_index,
            removed: entry.removed,
        }
    }
}

#[async_trait]
impl LogStore for MdbxLogStore {
    async fn put_logs(&self, logs: &[StoredLog]) -> LogStoreResult<()> {
        if logs.is_empty() {
            return Ok(());
        }

        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        for log in logs {
            let log_key = LogKey::new(log.block_number, log.log_index);
            let entry = Self::log_to_entry(log);

            // Store in primary Logs table
            tx.put::<Logs>(log_key, BincodeValue(entry))
                .map_err(|e| db_err(e.to_string()))?;

            // Store in LogsByAddress index
            let addr_key = AddressLogKey::new(log.address, log.block_number, log.log_index);
            tx.put::<LogsByAddress>(addr_key, UnitKey)
                .map_err(|e| db_err(e.to_string()))?;
        }

        tx.commit().map_err(|e| db_err(e.to_string()))?;
        Ok(())
    }

    async fn get_logs(
        &self,
        filter: &LogFilter,
        max_results: usize,
    ) -> LogStoreResult<Vec<StoredLog>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        // Determine block range
        let (from_block, to_block) = self.resolve_block_range(&tx, filter)?;

        let mut results = Vec::new();

        // If filtering by specific addresses, use the address index
        if !filter.addresses.is_empty() {
            for address in &filter.addresses {
                if results.len() >= max_results {
                    break;
                }

                // Scan address index for the block range
                let start_key = AddressLogKey::new(*address, from_block, 0);
                let mut cursor = tx
                    .cursor_read::<LogsByAddress>()
                    .map_err(|e| db_err(e.to_string()))?;

                // Seek to start position
                if cursor
                    .seek(start_key)
                    .map_err(|e| db_err(e.to_string()))?
                    .is_none()
                {
                    continue;
                }

                // Iterate through matching entries
                loop {
                    let current = cursor.current().map_err(|e| db_err(e.to_string()))?;
                    match current {
                        Some((key, _)) => {
                            // Check if still within address and block range
                            if key.address != *address || key.block_number > to_block {
                                break;
                            }

                            // Fetch the actual log
                            let log_key = LogKey::new(key.block_number, key.log_index);
                            if let Some(entry) =
                                tx.get::<Logs>(log_key).map_err(|e| db_err(e.to_string()))?
                            {
                                let log =
                                    Self::entry_to_log(entry.0, key.block_number, key.log_index);

                                // Apply topic filters
                                if filter.matches(&log) {
                                    results.push(log);
                                    if results.len() >= max_results {
                                        break;
                                    }
                                }
                            }

                            // Move to next entry
                            if cursor.next().map_err(|e| db_err(e.to_string()))?.is_none() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        } else {
            // No address filter - scan the Logs table directly
            let start_key = LogKey::new(from_block, 0);
            let mut cursor = tx
                .cursor_read::<Logs>()
                .map_err(|e| db_err(e.to_string()))?;

            // Seek to start position
            if cursor
                .seek(start_key)
                .map_err(|e| db_err(e.to_string()))?
                .is_none()
            {
                return Ok(results);
            }

            // Iterate through logs in block range
            loop {
                let current = cursor.current().map_err(|e| db_err(e.to_string()))?;
                match current {
                    Some((key, entry)) => {
                        // Check if still within block range
                        if key.block_number > to_block {
                            break;
                        }

                        let log = Self::entry_to_log(entry.0, key.block_number, key.log_index);

                        // Apply all filters (address is already skipped since empty)
                        if filter.matches(&log) {
                            results.push(log);
                            if results.len() >= max_results {
                                break;
                            }
                        }

                        // Move to next entry
                        if cursor.next().map_err(|e| db_err(e.to_string()))?.is_none() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }

        // Sort by (block_number, log_index)
        results.sort_by(|a, b| {
            a.block_number
                .cmp(&b.block_number)
                .then_with(|| a.log_index.cmp(&b.log_index))
        });

        Ok(results)
    }

    async fn get_logs_by_block(&self, block_number: u64) -> LogStoreResult<Vec<StoredLog>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let mut results = Vec::new();
        let start_key = LogKey::new(block_number, 0);
        let mut cursor = tx
            .cursor_read::<Logs>()
            .map_err(|e| db_err(e.to_string()))?;

        // Seek to start of block
        if cursor
            .seek(start_key)
            .map_err(|e| db_err(e.to_string()))?
            .is_none()
        {
            return Ok(results);
        }

        // Iterate through logs in this block
        loop {
            let current = cursor.current().map_err(|e| db_err(e.to_string()))?;
            match current {
                Some((key, entry)) => {
                    if key.block_number != block_number {
                        break;
                    }

                    results.push(Self::entry_to_log(entry.0, key.block_number, key.log_index));

                    if cursor.next().map_err(|e| db_err(e.to_string()))?.is_none() {
                        break;
                    }
                }
                None => break,
            }
        }

        Ok(results)
    }

    async fn get_logs_by_block_hash(
        &self,
        block_hash: &[u8; 32],
    ) -> LogStoreResult<Vec<StoredLog>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        // Look up block number from hash
        let hash_key = super::tables::HashKey(*block_hash);
        let block_number = match tx
            .get::<BlocksByHash>(hash_key)
            .map_err(|e| db_err(e.to_string()))?
        {
            Some(key) => key.0,
            None => return Ok(Vec::new()),
        };

        drop(tx);

        self.get_logs_by_block(block_number).await
    }

    async fn delete_logs_by_block(&self, block_number: u64) -> LogStoreResult<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // First, collect all logs for this block to know what to delete from indices
        let mut logs_to_delete = Vec::new();
        {
            let read_tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
            let start_key = LogKey::new(block_number, 0);
            let mut cursor = read_tx
                .cursor_read::<Logs>()
                .map_err(|e| db_err(e.to_string()))?;

            if cursor
                .seek(start_key)
                .map_err(|e| db_err(e.to_string()))?
                .is_some()
            {
                loop {
                    let current = cursor.current().map_err(|e| db_err(e.to_string()))?;
                    match current {
                        Some((key, entry)) => {
                            if key.block_number != block_number {
                                break;
                            }
                            logs_to_delete.push((key, entry.0.address));
                            if cursor.next().map_err(|e| db_err(e.to_string()))?.is_none() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        // Delete from primary table and address index
        for (log_key, address) in logs_to_delete {
            tx.delete::<Logs>(log_key, None)
                .map_err(|e| db_err(e.to_string()))?;

            let addr_key = AddressLogKey::new(address, log_key.block_number, log_key.log_index);
            tx.delete::<LogsByAddress>(addr_key, None)
                .map_err(|e| db_err(e.to_string()))?;
        }

        // Delete bloom filter
        let bloom_key = BlockNumberKey::new(block_number);
        tx.delete::<BlockBlooms>(bloom_key, None)
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;
        Ok(())
    }

    async fn get_block_bloom(&self, block_number: u64) -> LogStoreResult<Option<[u8; 256]>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey::new(block_number);
        match tx
            .get::<BlockBlooms>(key)
            .map_err(|e| db_err(e.to_string()))?
        {
            Some(stored) => {
                if stored.0.bloom.len() == 256 {
                    let mut bloom = [0u8; 256];
                    bloom.copy_from_slice(&stored.0.bloom);
                    Ok(Some(bloom))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn put_block_bloom(&self, block_number: u64, bloom: &[u8; 256]) -> LogStoreResult<()> {
        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        let key = BlockNumberKey::new(block_number);
        let stored = StoredBloom {
            bloom: bloom.to_vec(),
        };

        tx.put::<BlockBlooms>(key, BincodeValue(stored))
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;
        Ok(())
    }
}

impl MdbxLogStore {
    /// Resolve block range from filter, handling block hash if present.
    fn resolve_block_range<TX: DbTx>(
        &self,
        tx: &TX,
        filter: &LogFilter,
    ) -> LogStoreResult<(u64, u64)> {
        // If block hash is specified, resolve to a single block
        if let Some(block_hash) = &filter.block_hash {
            let hash_key = super::tables::HashKey(*block_hash);
            match tx
                .get::<BlocksByHash>(hash_key)
                .map_err(|e| db_err(e.to_string()))?
            {
                Some(key) => return Ok((key.0, key.0)),
                None => return Ok((u64::MAX, 0)), // Empty range if hash not found
            }
        }

        // Use from_block and to_block, defaulting to 0 and MAX
        let from_block = filter.from_block.unwrap_or(0);
        let to_block = filter.to_block.unwrap_or(u64::MAX);

        Ok((from_block, to_block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdbx::Database;

    fn create_test_db() -> (Arc<DatabaseEnv>, tempfile::TempDir) {
        let (db, temp_dir) = Database::open_temp().unwrap();
        (Arc::clone(db.env()), temp_dir)
    }

    fn make_test_log(block_number: u64, log_index: u32, address_byte: u8) -> StoredLog {
        StoredLog {
            address: [address_byte; 20],
            topics: vec![[1u8; 32], [2u8; 32]],
            data: vec![0xab, 0xcd],
            block_number,
            block_hash: [0x11; 32],
            transaction_hash: [0x22; 32],
            transaction_index: 0,
            log_index,
            removed: false,
        }
    }

    #[tokio::test]
    async fn test_log_roundtrip() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxLogStore::new(db);

        let log = make_test_log(1, 0, 0x42);

        // Store
        store.put_logs(&[log.clone()]).await.unwrap();

        // Retrieve by block
        let retrieved = store.get_logs_by_block(1).await.unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].address, log.address);
        assert_eq!(retrieved[0].topics, log.topics);
        assert_eq!(retrieved[0].data, log.data);
    }

    #[tokio::test]
    async fn test_logs_by_block() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxLogStore::new(db);

        let logs = vec![
            make_test_log(10, 0, 1),
            make_test_log(10, 1, 2),
            make_test_log(10, 2, 1),
        ];

        store.put_logs(&logs).await.unwrap();

        let retrieved = store.get_logs_by_block(10).await.unwrap();
        assert_eq!(retrieved.len(), 3);

        // Should be ordered by log_index
        assert_eq!(retrieved[0].log_index, 0);
        assert_eq!(retrieved[1].log_index, 1);
        assert_eq!(retrieved[2].log_index, 2);
    }

    #[tokio::test]
    async fn test_logs_filter_by_address() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxLogStore::new(db);

        let logs = vec![
            make_test_log(10, 0, 1),
            make_test_log(10, 1, 2),
            make_test_log(10, 2, 1),
            make_test_log(11, 0, 3),
        ];

        store.put_logs(&logs).await.unwrap();

        // Filter by address [1; 20]
        let filter = LogFilter::new()
            .with_block_range(Some(10), Some(11))
            .with_address([1u8; 20]);

        let retrieved = store.get_logs(&filter, 100).await.unwrap();
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.iter().all(|l| l.address == [1u8; 20]));
    }

    #[tokio::test]
    async fn test_logs_filter_by_block_range() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxLogStore::new(db);

        let logs = vec![
            make_test_log(5, 0, 1),
            make_test_log(10, 0, 1),
            make_test_log(15, 0, 1),
            make_test_log(20, 0, 1),
        ];

        store.put_logs(&logs).await.unwrap();

        let filter = LogFilter::new().with_block_range(Some(10), Some(15));

        let retrieved = store.get_logs(&filter, 100).await.unwrap();
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved[0].block_number, 10);
        assert_eq!(retrieved[1].block_number, 15);
    }

    #[tokio::test]
    async fn test_delete_logs_by_block() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxLogStore::new(db);

        let logs = vec![make_test_log(10, 0, 1), make_test_log(10, 1, 2)];

        store.put_logs(&logs).await.unwrap();
        assert_eq!(store.get_logs_by_block(10).await.unwrap().len(), 2);

        store.delete_logs_by_block(10).await.unwrap();
        assert!(store.get_logs_by_block(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_block_bloom() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxLogStore::new(db);

        // No bloom initially
        assert!(store.get_block_bloom(1).await.unwrap().is_none());

        // Store bloom
        let bloom = [0xffu8; 256];
        store.put_block_bloom(1, &bloom).await.unwrap();

        // Retrieve bloom
        let retrieved = store.get_block_bloom(1).await.unwrap().unwrap();
        assert_eq!(retrieved, bloom);
    }

    #[tokio::test]
    async fn test_max_results() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxLogStore::new(db);

        // Store many logs
        let logs: Vec<_> = (0..100).map(|i| make_test_log(10, i, 1)).collect();
        store.put_logs(&logs).await.unwrap();

        // Limit results
        let filter = LogFilter::new().with_block_range(Some(10), Some(10));
        let retrieved = store.get_logs(&filter, 5).await.unwrap();
        assert_eq!(retrieved.len(), 5);
    }
}
