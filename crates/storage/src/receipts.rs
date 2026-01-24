//! Receipt storage trait for persisting transaction receipts.
//!
//! This module provides the [`ReceiptStore`] trait for storing and retrieving
//! transaction receipts. The RPC layer uses this interface to serve
//! `eth_getTransactionReceipt` requests.
//!
//! # Usage
//!
//! ```ignore
//! use cipherbft_storage::ReceiptStore;
//! use cipherbft_storage::mdbx::MdbxReceiptStore;
//!
//! let store = MdbxReceiptStore::new(db);
//! store.put_receipt(&receipt).await?;
//! let retrieved = store.get_receipt(&tx_hash).await?;
//! ```

use async_trait::async_trait;

use crate::error::StorageError;

/// Result type for receipt storage operations.
pub type ReceiptStoreResult<T> = Result<T, StorageError>;

/// Transaction receipt data structure.
///
/// Contains all the information returned by `eth_getTransactionReceipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Transaction hash (32 bytes)
    pub transaction_hash: [u8; 32],
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
    /// Contract address created (20 bytes), if any
    pub contract_address: Option<[u8; 20]>,
    /// Gas used by this transaction
    pub gas_used: u64,
    /// Cumulative gas used in block up to and including this tx
    pub cumulative_gas_used: u64,
    /// Success status (true = success, false = revert)
    pub status: bool,
    /// Logs emitted by this transaction
    pub logs: Vec<Log>,
    /// Logs bloom filter (256 bytes)
    pub logs_bloom: Vec<u8>,
    /// Effective gas price used
    pub effective_gas_price: u64,
    /// Transaction type (0 = legacy, 1 = EIP-2930, 2 = EIP-1559)
    pub transaction_type: u8,
}

/// Log entry emitted by a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    /// Contract address that emitted the log (20 bytes)
    pub address: [u8; 20],
    /// Indexed topics (up to 4, each 32 bytes)
    pub topics: Vec<[u8; 32]>,
    /// Non-indexed log data
    pub data: Vec<u8>,
    /// Log index within the block
    pub log_index: u32,
    /// Transaction index within the block
    pub transaction_index: u32,
}

/// Trait for storing and retrieving transaction receipts.
///
/// This trait provides async storage operations for transaction receipts.
/// Receipts are indexed by their transaction hash, with a secondary index
/// by block number for efficient block-based queries.
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access from multiple RPC handlers.
#[async_trait]
pub trait ReceiptStore: Send + Sync {
    /// Store a receipt.
    ///
    /// The receipt is stored using its transaction hash as the primary key.
    /// An entry is also added to the block index.
    ///
    /// # Arguments
    /// * `receipt` - The receipt to store
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn put_receipt(&self, receipt: &Receipt) -> ReceiptStoreResult<()>;

    /// Store multiple receipts for a block.
    ///
    /// This is more efficient than calling `put_receipt` multiple times
    /// as it batches all writes into a single transaction.
    ///
    /// # Arguments
    /// * `receipts` - The receipts to store
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn put_receipts(&self, receipts: &[Receipt]) -> ReceiptStoreResult<()>;

    /// Retrieve a receipt by its transaction hash.
    ///
    /// # Arguments
    /// * `tx_hash` - Transaction hash (32 bytes)
    ///
    /// # Returns
    /// * `Ok(Some(receipt))` if the receipt exists
    /// * `Ok(None)` if the receipt does not exist
    /// * `Err(...)` if the storage operation fails
    async fn get_receipt(&self, tx_hash: &[u8; 32]) -> ReceiptStoreResult<Option<Receipt>>;

    /// Retrieve all receipts for a block.
    ///
    /// # Arguments
    /// * `block_number` - The block number
    ///
    /// # Returns
    /// * `Ok(receipts)` - List of receipts in transaction order
    /// * `Err(...)` if the storage operation fails
    async fn get_receipts_by_block(&self, block_number: u64) -> ReceiptStoreResult<Vec<Receipt>>;

    /// Check if a receipt exists.
    ///
    /// This is a lightweight operation that does not deserialize the receipt.
    ///
    /// # Arguments
    /// * `tx_hash` - Transaction hash (32 bytes)
    ///
    /// # Returns
    /// * `Ok(true)` if the receipt exists
    /// * `Ok(false)` if the receipt does not exist
    /// * `Err(...)` if the storage operation fails
    async fn has_receipt(&self, tx_hash: &[u8; 32]) -> ReceiptStoreResult<bool>;

    /// Delete all receipts for a block (for pruning).
    ///
    /// Removes all receipts associated with the given block number.
    /// This is typically used during garbage collection/pruning.
    ///
    /// # Arguments
    /// * `block_number` - The block number to delete receipts for
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    /// Does not return an error if no receipts exist for the block.
    async fn delete_receipts_by_block(&self, block_number: u64) -> ReceiptStoreResult<()>;
}
