//! Transaction storage trait for persisting transactions.
//!
//! This module provides the [`TransactionStore`] trait for storing and retrieving
//! transactions. The RPC layer uses this interface to serve `eth_getTransactionByHash`
//! requests.
//!
//! # Usage
//!
//! ```ignore
//! use cipherbft_storage::TransactionStore;
//! use cipherbft_storage::mdbx::MdbxTransactionStore;
//!
//! let store = MdbxTransactionStore::new(db);
//! store.put_transaction(&tx).await?;
//! let retrieved = store.get_transaction(&tx_hash).await?;
//! ```

use async_trait::async_trait;

use crate::error::StorageError;

/// Result type for transaction storage operations.
pub type TransactionStoreResult<T> = Result<T, StorageError>;

/// Stored transaction representation for persistence.
///
/// Contains all the information returned by `eth_getTransactionByHash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Transaction hash (32 bytes)
    pub hash: [u8; 32],
    /// Block number where the transaction was included
    pub block_number: u64,
    /// Block hash (32 bytes)
    pub block_hash: [u8; 32],
    /// Transaction index within the block
    pub transaction_index: u32,
    /// Sender address (20 bytes)
    pub from: [u8; 20],
    /// Recipient address (20 bytes), None for contract creation
    pub to: Option<[u8; 20]>,
    /// Transaction value (U256 as big-endian bytes)
    pub value: [u8; 32],
    /// Transaction input data
    pub input: Vec<u8>,
    /// Sender nonce
    pub nonce: u64,
    /// Gas limit
    pub gas: u64,
    /// Gas price (legacy transactions)
    pub gas_price: Option<u64>,
    /// Max fee per gas (EIP-1559)
    pub max_fee_per_gas: Option<u64>,
    /// Max priority fee per gas (EIP-1559)
    pub max_priority_fee_per_gas: Option<u64>,
    /// Chain ID
    pub chain_id: Option<u64>,
    /// Signature v value
    pub v: u64,
    /// Signature r value (32 bytes)
    pub r: [u8; 32],
    /// Signature s value (32 bytes)
    pub s: [u8; 32],
    /// Transaction type (0 = legacy, 1 = EIP-2930, 2 = EIP-1559)
    pub transaction_type: u8,
}

/// Trait for storing and retrieving transactions.
///
/// This trait provides async storage operations for transactions.
/// Transactions are indexed by their hash for efficient hash-based queries,
/// with a secondary index by block number for block-based queries.
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access from multiple RPC handlers.
#[async_trait]
pub trait TransactionStore: Send + Sync {
    /// Store a single transaction.
    ///
    /// The transaction is stored using its hash as the primary key.
    /// An entry is also added to the block index.
    ///
    /// # Arguments
    /// * `tx` - The transaction to store
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn put_transaction(&self, tx: &Transaction) -> TransactionStoreResult<()>;

    /// Retrieve a transaction by its hash.
    ///
    /// # Arguments
    /// * `hash` - Transaction hash (32 bytes)
    ///
    /// # Returns
    /// * `Ok(Some(tx))` if the transaction exists
    /// * `Ok(None)` if the transaction does not exist
    /// * `Err(...)` if the storage operation fails
    async fn get_transaction(&self, hash: &[u8; 32])
        -> TransactionStoreResult<Option<Transaction>>;

    /// Store multiple transactions in a batch (more efficient).
    ///
    /// This is more efficient than calling `put_transaction` multiple times
    /// as it batches all writes into a single database transaction.
    ///
    /// # Arguments
    /// * `txs` - The transactions to store
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn put_transactions(&self, txs: &[Transaction]) -> TransactionStoreResult<()>;

    /// Retrieve all transactions for a block.
    ///
    /// # Arguments
    /// * `block_number` - The block number
    ///
    /// # Returns
    /// * `Ok(txs)` - List of transactions in transaction index order
    /// * `Err(...)` if the storage operation fails
    async fn get_transactions_by_block(
        &self,
        block_number: u64,
    ) -> TransactionStoreResult<Vec<Transaction>>;

    /// Check if a transaction exists.
    ///
    /// This is a lightweight operation that does not deserialize the transaction.
    ///
    /// # Arguments
    /// * `hash` - Transaction hash (32 bytes)
    ///
    /// # Returns
    /// * `Ok(true)` if the transaction exists
    /// * `Ok(false)` if the transaction does not exist
    /// * `Err(...)` if the storage operation fails
    async fn has_transaction(&self, hash: &[u8; 32]) -> TransactionStoreResult<bool>;

    /// Delete all transactions for a block (for pruning).
    ///
    /// Removes all transactions associated with the given block number.
    /// This is typically used during garbage collection/pruning.
    ///
    /// # Arguments
    /// * `block_number` - The block number to delete transactions for
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    /// Does not return an error if no transactions exist for the block.
    async fn delete_transactions_by_block(&self, block_number: u64) -> TransactionStoreResult<()>;
}
