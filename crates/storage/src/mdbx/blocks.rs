//! MDBX-based implementation of BlockStore.
//!
//! This module provides the [`MdbxBlockStore`] implementation of [`BlockStore`] trait
//! using MDBX as the backing storage engine for block persistence.

use std::sync::Arc;

use async_trait::async_trait;
use reth_db::Database;
use reth_db_api::cursor::DbCursorRO;
use reth_db_api::transaction::{DbTx, DbTxMut};

use super::database::DatabaseEnv;
use super::tables::{BincodeValue, BlockNumberKey, Blocks, BlocksByHash, HashKey, StoredBlock};
use crate::blocks::{Block, BlockStore, BlockStoreResult};
use crate::error::StorageError;

/// Helper to convert database errors to storage errors.
fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// MDBX-based block storage implementation.
///
/// This implementation uses reth-db (MDBX) for persistent storage of blocks.
/// Blocks are stored in the `Blocks` table indexed by block number,
/// with a secondary index in `BlocksByHash` for hash-based queries.
///
/// # Thread Safety
///
/// This type is thread-safe and can be shared across threads using `Arc`.
/// The underlying MDBX database handles concurrent access.
///
/// # Example
///
/// ```ignore
/// use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxBlockStore};
/// use cipherbft_storage::BlockStore;
/// use std::sync::Arc;
///
/// let config = DatabaseConfig::new("/path/to/db");
/// let db = Arc::new(Database::open(config)?);
/// let store = MdbxBlockStore::new(db.env().clone());
///
/// store.put_block(&block).await?;
/// ```
pub struct MdbxBlockStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxBlockStore {
    /// Create a new MDBX block store.
    ///
    /// # Arguments
    /// * `db` - Shared reference to the MDBX database environment
    pub fn new(db: Arc<DatabaseEnv>) -> Self {
        Self { db }
    }

    /// Convert a Block to StoredBlock for persistence.
    fn block_to_stored(block: &Block) -> StoredBlock {
        StoredBlock {
            hash: block.hash,
            number: block.number,
            parent_hash: block.parent_hash,
            ommers_hash: block.ommers_hash,
            beneficiary: block.beneficiary,
            state_root: block.state_root,
            transactions_root: block.transactions_root,
            receipts_root: block.receipts_root,
            logs_bloom: block.logs_bloom.clone(),
            difficulty: block.difficulty,
            gas_limit: block.gas_limit,
            gas_used: block.gas_used,
            timestamp: block.timestamp,
            extra_data: block.extra_data.clone(),
            mix_hash: block.mix_hash,
            nonce: block.nonce,
            base_fee_per_gas: block.base_fee_per_gas,
            transaction_hashes: block.transaction_hashes.clone(),
            transaction_count: block.transaction_count,
            total_difficulty: block.total_difficulty,
            size: block.size,
        }
    }

    /// Convert a StoredBlock back to a Block.
    fn stored_to_block(stored: StoredBlock) -> Block {
        Block {
            hash: stored.hash,
            number: stored.number,
            parent_hash: stored.parent_hash,
            ommers_hash: stored.ommers_hash,
            beneficiary: stored.beneficiary,
            state_root: stored.state_root,
            transactions_root: stored.transactions_root,
            receipts_root: stored.receipts_root,
            logs_bloom: stored.logs_bloom,
            difficulty: stored.difficulty,
            gas_limit: stored.gas_limit,
            gas_used: stored.gas_used,
            timestamp: stored.timestamp,
            extra_data: stored.extra_data,
            mix_hash: stored.mix_hash,
            nonce: stored.nonce,
            base_fee_per_gas: stored.base_fee_per_gas,
            transaction_hashes: stored.transaction_hashes,
            transaction_count: stored.transaction_count,
            total_difficulty: stored.total_difficulty,
            size: stored.size,
        }
    }
}

#[async_trait]
impl BlockStore for MdbxBlockStore {
    async fn put_block(&self, block: &Block) -> BlockStoreResult<()> {
        let stored = Self::block_to_stored(block);
        let number_key = BlockNumberKey::new(block.number);
        let hash_key = HashKey(block.hash);

        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Store the block by number
        tx.put::<Blocks>(number_key, BincodeValue(stored))
            .map_err(|e| db_err(e.to_string()))?;

        // Store the hash -> number index
        tx.put::<BlocksByHash>(hash_key, number_key)
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;
        Ok(())
    }

    async fn get_block_by_number(&self, number: u64) -> BlockStoreResult<Option<Block>> {
        let key = BlockNumberKey::new(number);

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = tx.get::<Blocks>(key).map_err(|e| db_err(e.to_string()))?;

        match result {
            Some(bincode_value) => {
                let block = Self::stored_to_block(bincode_value.0);
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    async fn get_block_by_hash(&self, hash: &[u8; 32]) -> BlockStoreResult<Option<Block>> {
        let hash_key = HashKey(*hash);

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        // First, get the block number from the hash index
        let number_key = tx
            .get::<BlocksByHash>(hash_key)
            .map_err(|e| db_err(e.to_string()))?;

        match number_key {
            Some(key) => {
                // Then, get the block by number
                let result = tx.get::<Blocks>(key).map_err(|e| db_err(e.to_string()))?;
                match result {
                    Some(bincode_value) => {
                        let block = Self::stored_to_block(bincode_value.0);
                        Ok(Some(block))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn get_block_number_by_hash(&self, hash: &[u8; 32]) -> BlockStoreResult<Option<u64>> {
        let hash_key = HashKey(*hash);

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = tx
            .get::<BlocksByHash>(hash_key)
            .map_err(|e| db_err(e.to_string()))?;

        Ok(result.map(|key| key.0))
    }

    async fn get_latest_block_number(&self) -> BlockStoreResult<Option<u64>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let mut cursor = tx
            .cursor_read::<Blocks>()
            .map_err(|e| db_err(e.to_string()))?;

        // Seek to the last entry
        match cursor.last().map_err(|e| db_err(e.to_string()))? {
            Some((key, _)) => Ok(Some(key.0)),
            None => Ok(None),
        }
    }

    async fn get_earliest_block_number(&self) -> BlockStoreResult<Option<u64>> {
        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let mut cursor = tx
            .cursor_read::<Blocks>()
            .map_err(|e| db_err(e.to_string()))?;

        // Seek to the first entry
        match cursor.first().map_err(|e| db_err(e.to_string()))? {
            Some((key, _)) => Ok(Some(key.0)),
            None => Ok(None),
        }
    }

    async fn has_block(&self, number: u64) -> BlockStoreResult<bool> {
        let key = BlockNumberKey::new(number);

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = tx.get::<Blocks>(key).map_err(|e| db_err(e.to_string()))?;

        Ok(result.is_some())
    }

    async fn delete_block(&self, number: u64) -> BlockStoreResult<()> {
        let number_key = BlockNumberKey::new(number);

        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Get the block to find its hash
        if let Some(stored) = tx
            .get::<Blocks>(number_key)
            .map_err(|e| db_err(e.to_string()))?
        {
            let hash_key = HashKey(stored.0.hash);

            // Delete the hash index entry
            tx.delete::<BlocksByHash>(hash_key, None)
                .map_err(|e| db_err(e.to_string()))?;
        }

        // Delete the block
        tx.delete::<Blocks>(number_key, None)
            .map_err(|e| db_err(e.to_string()))?;

        tx.commit().map_err(|e| db_err(e.to_string()))?;
        Ok(())
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

    fn make_test_block(number: u64) -> Block {
        let mut hash = [0u8; 32];
        hash[0] = (number & 0xff) as u8;
        hash[1] = ((number >> 8) & 0xff) as u8;

        let mut block = Block {
            hash,
            number,
            parent_hash: [number.saturating_sub(1) as u8; 32],
            ommers_hash: [0u8; 32],
            beneficiary: [1u8; 20],
            state_root: [2u8; 32],
            transactions_root: [3u8; 32],
            receipts_root: [4u8; 32],
            logs_bloom: vec![0u8; 256],
            difficulty: [0u8; 32],
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1700000000 + number,
            extra_data: vec![],
            mix_hash: [5u8; 32],
            nonce: [0u8; 8],
            base_fee_per_gas: Some(1_000_000_000),
            transaction_hashes: vec![[6u8; 32], [7u8; 32]],
            transaction_count: 2,
            total_difficulty: [0u8; 32],
            size: 0, // Calculated below
        };
        block.size = block.calculate_size();
        block
    }

    #[tokio::test]
    async fn test_block_roundtrip() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBlockStore::new(db);

        let block = make_test_block(1);
        let block_hash = block.hash;

        // Store
        store.put_block(&block).await.unwrap();

        // Retrieve by number
        let retrieved = store.get_block_by_number(1).await.unwrap().unwrap();
        assert_eq!(retrieved.number, block.number);
        assert_eq!(retrieved.hash, block.hash);
        assert_eq!(retrieved.gas_limit, block.gas_limit);
        assert_eq!(retrieved.transaction_count, block.transaction_count);

        // Retrieve by hash
        let retrieved = store.get_block_by_hash(&block_hash).await.unwrap().unwrap();
        assert_eq!(retrieved.number, block.number);
    }

    #[tokio::test]
    async fn test_block_has() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBlockStore::new(db);

        let block = make_test_block(2);

        assert!(!store.has_block(2).await.unwrap());
        store.put_block(&block).await.unwrap();
        assert!(store.has_block(2).await.unwrap());
    }

    #[tokio::test]
    async fn test_block_by_hash() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBlockStore::new(db);

        let block = make_test_block(10);
        let block_hash = block.hash;

        store.put_block(&block).await.unwrap();

        // Get number by hash
        let number = store
            .get_block_number_by_hash(&block_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(number, 10);

        // Get full block by hash
        let retrieved = store.get_block_by_hash(&block_hash).await.unwrap().unwrap();
        assert_eq!(retrieved.number, 10);
    }

    #[tokio::test]
    async fn test_latest_block_number() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBlockStore::new(db);

        // No blocks yet
        assert!(store.get_latest_block_number().await.unwrap().is_none());

        // Add some blocks
        store.put_block(&make_test_block(1)).await.unwrap();
        store.put_block(&make_test_block(5)).await.unwrap();
        store.put_block(&make_test_block(3)).await.unwrap();

        // Should return highest
        let latest = store.get_latest_block_number().await.unwrap().unwrap();
        assert_eq!(latest, 5);
    }

    #[tokio::test]
    async fn test_earliest_block_number() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBlockStore::new(db);

        // No blocks yet
        assert!(store.get_earliest_block_number().await.unwrap().is_none());

        // Add some blocks (not starting from 0)
        store.put_block(&make_test_block(5)).await.unwrap();
        store.put_block(&make_test_block(10)).await.unwrap();
        store.put_block(&make_test_block(7)).await.unwrap();

        // Should return lowest
        let earliest = store.get_earliest_block_number().await.unwrap().unwrap();
        assert_eq!(earliest, 5);
    }

    #[tokio::test]
    async fn test_delete_block() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBlockStore::new(db);

        let block = make_test_block(20);
        let block_hash = block.hash;

        // Store
        store.put_block(&block).await.unwrap();
        assert!(store.has_block(20).await.unwrap());

        // Delete
        store.delete_block(20).await.unwrap();

        // Verify deleted
        assert!(!store.has_block(20).await.unwrap());
        assert!(store
            .get_block_number_by_hash(&block_hash)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_block_not_found() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxBlockStore::new(db);

        let result = store.get_block_by_number(999).await.unwrap();
        assert!(result.is_none());

        let missing_hash = [0u8; 32];
        let result = store.get_block_by_hash(&missing_hash).await.unwrap();
        assert!(result.is_none());
    }
}
