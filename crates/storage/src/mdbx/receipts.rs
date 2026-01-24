//! MDBX-based implementation of ReceiptStore.
//!
//! This module provides the [`MdbxReceiptStore`] implementation of [`ReceiptStore`] trait
//! using MDBX as the backing storage engine for transaction receipt persistence.

use std::sync::Arc;

use async_trait::async_trait;
use reth_db::Database;
use reth_db_api::transaction::{DbTx, DbTxMut};

use super::database::DatabaseEnv;
use super::tables::{
    BincodeValue, BlockNumberKey, HashKey, ReceiptsByBlock, Receipts, StoredLog, StoredReceipt,
};
use crate::error::StorageError;
use crate::receipts::{Log, Receipt, ReceiptStore, ReceiptStoreResult};

/// Helper to convert database errors to storage errors.
fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// MDBX-based receipt storage implementation.
///
/// This implementation uses reth-db (MDBX) for persistent storage of transaction
/// receipts. Receipts are stored in the `Receipts` table indexed by transaction hash,
/// with a secondary index in `ReceiptsByBlock` for block-based queries.
///
/// # Thread Safety
///
/// This type is thread-safe and can be shared across threads using `Arc`.
/// The underlying MDBX database handles concurrent access.
///
/// # Example
///
/// ```ignore
/// use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxReceiptStore};
/// use cipherbft_storage::ReceiptStore;
/// use std::sync::Arc;
///
/// let config = DatabaseConfig::new("/path/to/db");
/// let db = Arc::new(Database::open(config)?);
/// let store = MdbxReceiptStore::new(db.env().clone());
///
/// store.put_receipt(&receipt).await?;
/// ```
pub struct MdbxReceiptStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxReceiptStore {
    /// Create a new MDBX receipt store.
    ///
    /// # Arguments
    /// * `db` - Shared reference to the MDBX database environment
    pub fn new(db: Arc<DatabaseEnv>) -> Self {
        Self { db }
    }

    /// Convert a Receipt to StoredReceipt for persistence.
    fn receipt_to_stored(receipt: &Receipt) -> StoredReceipt {
        StoredReceipt {
            transaction_hash: receipt.transaction_hash,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
            transaction_index: receipt.transaction_index,
            from: receipt.from,
            to: receipt.to,
            contract_address: receipt.contract_address,
            gas_used: receipt.gas_used,
            cumulative_gas_used: receipt.cumulative_gas_used,
            status: if receipt.status { 1 } else { 0 },
            logs: receipt.logs.iter().map(Self::log_to_stored).collect(),
            logs_bloom: receipt.logs_bloom.clone(),
            effective_gas_price: receipt.effective_gas_price,
            transaction_type: receipt.transaction_type,
        }
    }

    /// Convert a StoredReceipt back to a Receipt.
    fn stored_to_receipt(stored: StoredReceipt) -> Receipt {
        Receipt {
            transaction_hash: stored.transaction_hash,
            block_number: stored.block_number,
            block_hash: stored.block_hash,
            transaction_index: stored.transaction_index,
            from: stored.from,
            to: stored.to,
            contract_address: stored.contract_address,
            gas_used: stored.gas_used,
            cumulative_gas_used: stored.cumulative_gas_used,
            status: stored.status != 0,
            logs: stored.logs.into_iter().map(Self::stored_to_log).collect(),
            logs_bloom: stored.logs_bloom,
            effective_gas_price: stored.effective_gas_price,
            transaction_type: stored.transaction_type,
        }
    }

    /// Convert a Log to StoredLog for persistence.
    fn log_to_stored(log: &Log) -> StoredLog {
        StoredLog {
            address: log.address,
            topics: log.topics.clone(),
            data: log.data.clone(),
            log_index: log.log_index,
            transaction_index: log.transaction_index,
        }
    }

    /// Convert a StoredLog back to a Log.
    fn stored_to_log(stored: StoredLog) -> Log {
        Log {
            address: stored.address,
            topics: stored.topics,
            data: stored.data,
            log_index: stored.log_index,
            transaction_index: stored.transaction_index,
        }
    }
}

#[async_trait]
impl ReceiptStore for MdbxReceiptStore {
    async fn put_receipt(&self, receipt: &Receipt) -> ReceiptStoreResult<()> {
        let stored = Self::receipt_to_stored(receipt);
        let tx_key = HashKey(receipt.transaction_hash);
        let block_key = BlockNumberKey::new(receipt.block_number);

        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Store the receipt by transaction hash
        tx.put::<Receipts>(tx_key, BincodeValue(stored))
            .map_err(|e| db_err(e.to_string()))?;

        // Update block index
        let mut tx_hashes: Vec<[u8; 32]> = tx
            .get::<ReceiptsByBlock>(block_key)
            .map_err(|e| db_err(e.to_string()))?
            .map(|v| v.0)
            .unwrap_or_default();

        if !tx_hashes.contains(&receipt.transaction_hash) {
            tx_hashes.push(receipt.transaction_hash);
            tx.put::<ReceiptsByBlock>(block_key, BincodeValue(tx_hashes))
                .map_err(|e| db_err(e.to_string()))?;
        }

        tx.commit().map_err(|e| db_err(e.to_string()))?;
        Ok(())
    }

    async fn put_receipts(&self, receipts: &[Receipt]) -> ReceiptStoreResult<()> {
        if receipts.is_empty() {
            return Ok(());
        }

        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Group receipts by block number for efficient block index updates
        let mut block_receipts: std::collections::HashMap<u64, Vec<[u8; 32]>> =
            std::collections::HashMap::new();

        for receipt in receipts {
            let stored = Self::receipt_to_stored(receipt);
            let tx_key = HashKey(receipt.transaction_hash);

            // Store the receipt by transaction hash
            tx.put::<Receipts>(tx_key, BincodeValue(stored))
                .map_err(|e| db_err(e.to_string()))?;

            // Track for block index
            block_receipts
                .entry(receipt.block_number)
                .or_default()
                .push(receipt.transaction_hash);
        }

        // Update block indices
        for (block_number, tx_hashes) in block_receipts {
            let block_key = BlockNumberKey::new(block_number);

            // Get existing hashes (if any) and append new ones
            let mut existing: Vec<[u8; 32]> = tx
                .get::<ReceiptsByBlock>(block_key)
                .map_err(|e| db_err(e.to_string()))?
                .map(|v| v.0)
                .unwrap_or_default();

            for hash in tx_hashes {
                if !existing.contains(&hash) {
                    existing.push(hash);
                }
            }

            tx.put::<ReceiptsByBlock>(block_key, BincodeValue(existing))
                .map_err(|e| db_err(e.to_string()))?;
        }

        tx.commit().map_err(|e| db_err(e.to_string()))?;
        Ok(())
    }

    async fn get_receipt(&self, tx_hash: &[u8; 32]) -> ReceiptStoreResult<Option<Receipt>> {
        let key = HashKey(*tx_hash);

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = tx
            .get::<Receipts>(key)
            .map_err(|e| db_err(e.to_string()))?;

        match result {
            Some(bincode_value) => {
                let receipt = Self::stored_to_receipt(bincode_value.0);
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }

    async fn get_receipts_by_block(&self, block_number: u64) -> ReceiptStoreResult<Vec<Receipt>> {
        let block_key = BlockNumberKey::new(block_number);

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        // Get transaction hashes for this block
        let tx_hashes: Vec<[u8; 32]> = tx
            .get::<ReceiptsByBlock>(block_key)
            .map_err(|e| db_err(e.to_string()))?
            .map(|v| v.0)
            .unwrap_or_default();

        // Fetch each receipt
        let mut receipts = Vec::with_capacity(tx_hashes.len());
        for hash in tx_hashes {
            let key = HashKey(hash);
            if let Some(stored) = tx.get::<Receipts>(key).map_err(|e| db_err(e.to_string()))? {
                receipts.push(Self::stored_to_receipt(stored.0));
            }
        }

        // Sort by transaction index
        receipts.sort_by_key(|r| r.transaction_index);

        Ok(receipts)
    }

    async fn has_receipt(&self, tx_hash: &[u8; 32]) -> ReceiptStoreResult<bool> {
        let key = HashKey(*tx_hash);

        let tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = tx
            .get::<Receipts>(key)
            .map_err(|e| db_err(e.to_string()))?;

        Ok(result.is_some())
    }

    async fn delete_receipts_by_block(&self, block_number: u64) -> ReceiptStoreResult<()> {
        let block_key = BlockNumberKey::new(block_number);

        let tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Get transaction hashes for this block
        let tx_hashes: Vec<[u8; 32]> = tx
            .get::<ReceiptsByBlock>(block_key)
            .map_err(|e| db_err(e.to_string()))?
            .map(|v| v.0)
            .unwrap_or_default();

        // Delete each receipt
        for hash in tx_hashes {
            let key = HashKey(hash);
            tx.delete::<Receipts>(key, None)
                .map_err(|e| db_err(e.to_string()))?;
        }

        // Delete the block index entry
        tx.delete::<ReceiptsByBlock>(block_key, None)
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

    fn make_test_receipt(block_number: u64, tx_index: u32) -> Receipt {
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = (block_number & 0xff) as u8;
        tx_hash[1] = (tx_index & 0xff) as u8;

        Receipt {
            transaction_hash: tx_hash,
            block_number,
            block_hash: [block_number as u8; 32],
            transaction_index: tx_index,
            from: [1u8; 20],
            to: Some([2u8; 20]),
            contract_address: None,
            gas_used: 21000,
            cumulative_gas_used: 21000 * (tx_index as u64 + 1),
            status: true,
            logs: vec![Log {
                address: [3u8; 20],
                topics: vec![[4u8; 32]],
                data: vec![5, 6, 7],
                log_index: 0,
                transaction_index: tx_index,
            }],
            logs_bloom: vec![0u8; 256],
            effective_gas_price: 1_000_000_000,
            transaction_type: 2,
        }
    }

    #[tokio::test]
    async fn test_receipt_roundtrip() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxReceiptStore::new(db);

        let receipt = make_test_receipt(1, 0);
        let tx_hash = receipt.transaction_hash;

        // Store
        store.put_receipt(&receipt).await.unwrap();

        // Retrieve
        let retrieved = store.get_receipt(&tx_hash).await.unwrap().unwrap();
        assert_eq!(retrieved.transaction_hash, receipt.transaction_hash);
        assert_eq!(retrieved.block_number, receipt.block_number);
        assert_eq!(retrieved.gas_used, receipt.gas_used);
        assert_eq!(retrieved.status, receipt.status);
        assert_eq!(retrieved.logs.len(), receipt.logs.len());
    }

    #[tokio::test]
    async fn test_receipt_has() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxReceiptStore::new(db);

        let receipt = make_test_receipt(2, 0);
        let tx_hash = receipt.transaction_hash;

        assert!(!store.has_receipt(&tx_hash).await.unwrap());
        store.put_receipt(&receipt).await.unwrap();
        assert!(store.has_receipt(&tx_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_receipts_by_block() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxReceiptStore::new(db);

        let block_number = 10;
        let receipts = vec![
            make_test_receipt(block_number, 0),
            make_test_receipt(block_number, 1),
            make_test_receipt(block_number, 2),
        ];

        // Store all receipts
        store.put_receipts(&receipts).await.unwrap();

        // Retrieve by block
        let retrieved = store.get_receipts_by_block(block_number).await.unwrap();
        assert_eq!(retrieved.len(), 3);

        // Should be sorted by transaction index
        for (i, r) in retrieved.iter().enumerate() {
            assert_eq!(r.transaction_index, i as u32);
        }
    }

    #[tokio::test]
    async fn test_delete_receipts_by_block() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxReceiptStore::new(db);

        let block_number = 20;
        let receipts = vec![
            make_test_receipt(block_number, 0),
            make_test_receipt(block_number, 1),
        ];
        let tx_hash = receipts[0].transaction_hash;

        // Store
        store.put_receipts(&receipts).await.unwrap();
        assert!(store.has_receipt(&tx_hash).await.unwrap());

        // Delete by block
        store.delete_receipts_by_block(block_number).await.unwrap();

        // Verify deleted
        assert!(!store.has_receipt(&tx_hash).await.unwrap());
        let retrieved = store.get_receipts_by_block(block_number).await.unwrap();
        assert!(retrieved.is_empty());
    }

    #[tokio::test]
    async fn test_receipt_not_found() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxReceiptStore::new(db);

        let missing_hash = [0u8; 32];
        let result = store.get_receipt(&missing_hash).await.unwrap();
        assert!(result.is_none());
    }
}
