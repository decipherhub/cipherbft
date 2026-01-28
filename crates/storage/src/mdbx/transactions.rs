//! MDBX-based implementation of TransactionStore.
//!
//! This module provides the [`MdbxTransactionStore`] implementation of [`TransactionStore`] trait
//! using MDBX as the backing storage engine for transaction persistence.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use cipherbft_metrics::storage::{
    STORAGE_BATCH_COMMIT, STORAGE_READ_LATENCY, STORAGE_WRITE_LATENCY,
};
use reth_db::Database;
use reth_db_api::transaction::{DbTx, DbTxMut};
use tracing::{debug, trace};

use super::database::DatabaseEnv;
use super::tables::{
    BincodeValue, BlockNumberKey, HashKey, StoredTransaction, Transactions, TransactionsByBlock,
};
use crate::error::StorageError;
use crate::transactions::{Transaction, TransactionStore, TransactionStoreResult};

/// Helper to convert database errors to storage errors.
fn db_err(e: impl std::fmt::Display) -> StorageError {
    StorageError::Database(e.to_string())
}

/// MDBX-based transaction storage implementation.
///
/// This implementation uses reth-db (MDBX) for persistent storage of transactions.
/// Transactions are stored in the `Transactions` table indexed by transaction hash,
/// with a secondary index in `TransactionsByBlock` for block-based queries.
///
/// # Thread Safety
///
/// This type is thread-safe and can be shared across threads using `Arc`.
/// The underlying MDBX database handles concurrent access.
///
/// # Example
///
/// ```ignore
/// use cipherbft_storage::mdbx::{Database, DatabaseConfig, MdbxTransactionStore};
/// use cipherbft_storage::TransactionStore;
/// use std::sync::Arc;
///
/// let config = DatabaseConfig::new("/path/to/db");
/// let db = Arc::new(Database::open(config)?);
/// let store = MdbxTransactionStore::new(db.env().clone());
///
/// store.put_transaction(&tx).await?;
/// ```
pub struct MdbxTransactionStore {
    db: Arc<DatabaseEnv>,
}

impl MdbxTransactionStore {
    /// Create a new MDBX transaction store.
    ///
    /// # Arguments
    /// * `db` - Shared reference to the MDBX database environment
    pub fn new(db: Arc<DatabaseEnv>) -> Self {
        Self { db }
    }

    /// Convert a Transaction to StoredTransaction for persistence.
    fn tx_to_stored(tx: &Transaction) -> StoredTransaction {
        StoredTransaction {
            hash: tx.hash,
            block_number: tx.block_number,
            block_hash: tx.block_hash,
            transaction_index: tx.transaction_index,
            from: tx.from,
            to: tx.to,
            value: tx.value,
            input: tx.input.clone(),
            nonce: tx.nonce,
            gas: tx.gas,
            gas_price: tx.gas_price,
            max_fee_per_gas: tx.max_fee_per_gas,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            chain_id: tx.chain_id,
            v: tx.v,
            r: tx.r,
            s: tx.s,
            transaction_type: tx.transaction_type,
        }
    }

    /// Convert a StoredTransaction back to a Transaction.
    fn stored_to_tx(stored: StoredTransaction) -> Transaction {
        Transaction {
            hash: stored.hash,
            block_number: stored.block_number,
            block_hash: stored.block_hash,
            transaction_index: stored.transaction_index,
            from: stored.from,
            to: stored.to,
            value: stored.value,
            input: stored.input,
            nonce: stored.nonce,
            gas: stored.gas,
            gas_price: stored.gas_price,
            max_fee_per_gas: stored.max_fee_per_gas,
            max_priority_fee_per_gas: stored.max_priority_fee_per_gas,
            chain_id: stored.chain_id,
            v: stored.v,
            r: stored.r,
            s: stored.s,
            transaction_type: stored.transaction_type,
        }
    }
}

#[async_trait]
impl TransactionStore for MdbxTransactionStore {
    async fn put_transaction(&self, tx: &Transaction) -> TransactionStoreResult<()> {
        let start = Instant::now();
        let stored = Self::tx_to_stored(tx);
        let tx_key = HashKey(tx.hash);
        let block_key = BlockNumberKey::new(tx.block_number);

        let db_tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Store the transaction by hash
        db_tx
            .put::<Transactions>(tx_key, BincodeValue(stored))
            .map_err(|e| db_err(e.to_string()))?;

        // Update block index
        let mut tx_hashes: Vec<[u8; 32]> = db_tx
            .get::<TransactionsByBlock>(block_key)
            .map_err(|e| db_err(e.to_string()))?
            .map(|v| v.0)
            .unwrap_or_default();

        if !tx_hashes.contains(&tx.hash) {
            tx_hashes.push(tx.hash);
            db_tx
                .put::<TransactionsByBlock>(block_key, BincodeValue(tx_hashes))
                .map_err(|e| db_err(e.to_string()))?;
        }

        let commit_start = Instant::now();
        db_tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["transactions"])
            .observe(start.elapsed().as_secs_f64());

        debug!(tx_hash = ?tx.hash, "Stored transaction");
        Ok(())
    }

    async fn get_transaction(
        &self,
        hash: &[u8; 32],
    ) -> TransactionStoreResult<Option<Transaction>> {
        let start = Instant::now();
        let key = HashKey(*hash);

        let db_tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = db_tx
            .get::<Transactions>(key)
            .map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["transactions"])
            .observe(start.elapsed().as_secs_f64());

        match result {
            Some(bincode_value) => {
                let tx = Self::stored_to_tx(bincode_value.0);
                trace!(tx_hash = ?hash, "Found transaction");
                Ok(Some(tx))
            }
            None => {
                trace!(tx_hash = ?hash, "Transaction not found");
                Ok(None)
            }
        }
    }

    async fn put_transactions(&self, txs: &[Transaction]) -> TransactionStoreResult<()> {
        if txs.is_empty() {
            return Ok(());
        }

        let start = Instant::now();
        let db_tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Group transactions by block number for efficient block index updates
        let mut block_txs: std::collections::HashMap<u64, Vec<[u8; 32]>> =
            std::collections::HashMap::new();

        for tx in txs {
            let stored = Self::tx_to_stored(tx);
            let tx_key = HashKey(tx.hash);

            // Store the transaction by hash
            db_tx
                .put::<Transactions>(tx_key, BincodeValue(stored))
                .map_err(|e| db_err(e.to_string()))?;

            // Track for block index
            block_txs.entry(tx.block_number).or_default().push(tx.hash);
        }

        // Update block indices
        for (block_number, tx_hashes) in block_txs {
            let block_key = BlockNumberKey::new(block_number);

            // Get existing hashes (if any) and append new ones
            let mut existing: Vec<[u8; 32]> = db_tx
                .get::<TransactionsByBlock>(block_key)
                .map_err(|e| db_err(e.to_string()))?
                .map(|v| v.0)
                .unwrap_or_default();

            for hash in tx_hashes {
                if !existing.contains(&hash) {
                    existing.push(hash);
                }
            }

            db_tx
                .put::<TransactionsByBlock>(block_key, BincodeValue(existing))
                .map_err(|e| db_err(e.to_string()))?;
        }

        let commit_start = Instant::now();
        db_tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["transactions"])
            .observe(start.elapsed().as_secs_f64());

        debug!(count = txs.len(), "Stored transactions in batch");
        Ok(())
    }

    async fn get_transactions_by_block(
        &self,
        block_number: u64,
    ) -> TransactionStoreResult<Vec<Transaction>> {
        let start = Instant::now();
        let block_key = BlockNumberKey::new(block_number);

        let db_tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;

        // Get transaction hashes for this block
        let tx_hashes: Vec<[u8; 32]> = db_tx
            .get::<TransactionsByBlock>(block_key)
            .map_err(|e| db_err(e.to_string()))?
            .map(|v| v.0)
            .unwrap_or_default();

        // Fetch each transaction
        let mut transactions = Vec::with_capacity(tx_hashes.len());
        for hash in tx_hashes {
            let key = HashKey(hash);
            if let Some(stored) = db_tx
                .get::<Transactions>(key)
                .map_err(|e| db_err(e.to_string()))?
            {
                transactions.push(Self::stored_to_tx(stored.0));
            }
        }

        // Sort by transaction index
        transactions.sort_by_key(|tx| tx.transaction_index);

        STORAGE_READ_LATENCY
            .with_label_values(&["transactions"])
            .observe(start.elapsed().as_secs_f64());

        trace!(
            block_number,
            count = transactions.len(),
            "Retrieved transactions by block"
        );
        Ok(transactions)
    }

    async fn has_transaction(&self, hash: &[u8; 32]) -> TransactionStoreResult<bool> {
        let start = Instant::now();
        let key = HashKey(*hash);

        let db_tx = self.db.tx().map_err(|e| db_err(e.to_string()))?;
        let result = db_tx
            .get::<Transactions>(key)
            .map_err(|e| db_err(e.to_string()))?;

        STORAGE_READ_LATENCY
            .with_label_values(&["transactions"])
            .observe(start.elapsed().as_secs_f64());

        Ok(result.is_some())
    }

    async fn delete_transactions_by_block(&self, block_number: u64) -> TransactionStoreResult<()> {
        let start = Instant::now();
        let block_key = BlockNumberKey::new(block_number);

        let db_tx = self.db.tx_mut().map_err(|e| db_err(e.to_string()))?;

        // Get transaction hashes for this block
        let tx_hashes: Vec<[u8; 32]> = db_tx
            .get::<TransactionsByBlock>(block_key)
            .map_err(|e| db_err(e.to_string()))?
            .map(|v| v.0)
            .unwrap_or_default();

        // Delete each transaction
        for hash in &tx_hashes {
            let key = HashKey(*hash);
            db_tx
                .delete::<Transactions>(key, None)
                .map_err(|e| db_err(e.to_string()))?;
        }

        // Delete the block index entry
        db_tx
            .delete::<TransactionsByBlock>(block_key, None)
            .map_err(|e| db_err(e.to_string()))?;

        let commit_start = Instant::now();
        db_tx.commit().map_err(|e| db_err(e.to_string()))?;
        STORAGE_BATCH_COMMIT
            .with_label_values(&[])
            .observe(commit_start.elapsed().as_secs_f64());

        STORAGE_WRITE_LATENCY
            .with_label_values(&["transactions"])
            .observe(start.elapsed().as_secs_f64());

        debug!(
            block_number,
            count = tx_hashes.len(),
            "Deleted transactions by block"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdbx::Database;

    fn create_test_db() -> (Arc<DatabaseEnv>, tempfile::TempDir) {
        let (db, temp_dir) = Database::open_temp().expect("Failed to create temp database");
        (Arc::clone(db.env()), temp_dir)
    }

    fn make_test_transaction(block_number: u64, tx_index: u32) -> Transaction {
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = (block_number & 0xff) as u8;
        tx_hash[1] = (tx_index & 0xff) as u8;

        Transaction {
            hash: tx_hash,
            block_number,
            block_hash: [block_number as u8; 32],
            transaction_index: tx_index,
            from: [1u8; 20],
            to: Some([2u8; 20]),
            value: [0u8; 32],
            input: vec![0xde, 0xad, 0xbe, 0xef],
            nonce: tx_index as u64,
            gas: 21000,
            gas_price: Some(1_000_000_000),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            chain_id: Some(1),
            v: 27,
            r: [3u8; 32],
            s: [4u8; 32],
            transaction_type: 0,
        }
    }

    #[tokio::test]
    async fn test_transaction_roundtrip() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxTransactionStore::new(db);

        let tx = make_test_transaction(1, 0);
        let tx_hash = tx.hash;

        // Store
        store
            .put_transaction(&tx)
            .await
            .expect("Failed to put transaction");

        // Retrieve
        let retrieved = store
            .get_transaction(&tx_hash)
            .await
            .expect("Failed to get transaction")
            .expect("Transaction should exist");

        assert_eq!(retrieved.hash, tx.hash);
        assert_eq!(retrieved.block_number, tx.block_number);
        assert_eq!(retrieved.from, tx.from);
        assert_eq!(retrieved.to, tx.to);
        assert_eq!(retrieved.nonce, tx.nonce);
        assert_eq!(retrieved.gas, tx.gas);
    }

    #[tokio::test]
    async fn test_transaction_has() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxTransactionStore::new(db);

        let tx = make_test_transaction(2, 0);
        let tx_hash = tx.hash;

        assert!(!store
            .has_transaction(&tx_hash)
            .await
            .expect("has_transaction failed"));
        store
            .put_transaction(&tx)
            .await
            .expect("Failed to put transaction");
        assert!(store
            .has_transaction(&tx_hash)
            .await
            .expect("has_transaction failed"));
    }

    #[tokio::test]
    async fn test_transactions_by_block() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxTransactionStore::new(db);

        let block_number = 10;
        let transactions = vec![
            make_test_transaction(block_number, 0),
            make_test_transaction(block_number, 1),
            make_test_transaction(block_number, 2),
        ];

        // Store all transactions
        store
            .put_transactions(&transactions)
            .await
            .expect("Failed to put transactions");

        // Retrieve by block
        let retrieved = store
            .get_transactions_by_block(block_number)
            .await
            .expect("Failed to get transactions by block");

        assert_eq!(retrieved.len(), 3);

        // Should be sorted by transaction index
        for (i, tx) in retrieved.iter().enumerate() {
            assert_eq!(tx.transaction_index, i as u32);
        }
    }

    #[tokio::test]
    async fn test_delete_transactions_by_block() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxTransactionStore::new(db);

        let block_number = 20;
        let transactions = vec![
            make_test_transaction(block_number, 0),
            make_test_transaction(block_number, 1),
        ];
        let tx_hash = transactions[0].hash;

        // Store
        store
            .put_transactions(&transactions)
            .await
            .expect("Failed to put transactions");
        assert!(store
            .has_transaction(&tx_hash)
            .await
            .expect("has_transaction failed"));

        // Delete by block
        store
            .delete_transactions_by_block(block_number)
            .await
            .expect("Failed to delete transactions");

        // Verify deleted
        assert!(!store
            .has_transaction(&tx_hash)
            .await
            .expect("has_transaction failed"));
        let retrieved = store
            .get_transactions_by_block(block_number)
            .await
            .expect("Failed to get transactions");
        assert!(retrieved.is_empty());
    }

    #[tokio::test]
    async fn test_transaction_not_found() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxTransactionStore::new(db);

        let missing_hash = [0u8; 32];
        let result = store
            .get_transaction(&missing_hash)
            .await
            .expect("get_transaction failed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_eip1559_transaction() {
        let (db, _temp_dir) = create_test_db();
        let store = MdbxTransactionStore::new(db);

        let mut tx = make_test_transaction(5, 0);
        tx.transaction_type = 2;
        tx.gas_price = None;
        tx.max_fee_per_gas = Some(100_000_000_000);
        tx.max_priority_fee_per_gas = Some(2_000_000_000);

        let tx_hash = tx.hash;

        // Store
        store
            .put_transaction(&tx)
            .await
            .expect("Failed to put transaction");

        // Retrieve
        let retrieved = store
            .get_transaction(&tx_hash)
            .await
            .expect("Failed to get transaction")
            .expect("Transaction should exist");

        assert_eq!(retrieved.transaction_type, 2);
        assert_eq!(retrieved.gas_price, None);
        assert_eq!(retrieved.max_fee_per_gas, Some(100_000_000_000));
        assert_eq!(retrieved.max_priority_fee_per_gas, Some(2_000_000_000));
    }
}
