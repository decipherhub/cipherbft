//! Block storage trait for persisting executed blocks.
//!
//! This module provides the [`BlockStore`] trait for storing and retrieving
//! blocks. The RPC layer uses this interface to serve `eth_getBlockByNumber`
//! and `eth_getBlockByHash` requests.
//!
//! # Usage
//!
//! ```ignore
//! use cipherbft_storage::BlockStore;
//! use cipherbft_storage::mdbx::MdbxBlockStore;
//!
//! let store = MdbxBlockStore::new(db);
//! store.put_block(&block).await?;
//! let retrieved = store.get_block_by_number(1).await?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

/// Result type for block storage operations.
pub type BlockStoreResult<T> = Result<T, StorageError>;

/// Stored block data structure.
///
/// Contains all the information returned by `eth_getBlockByNumber`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block hash (32 bytes)
    pub hash: [u8; 32],
    /// Block number
    pub number: u64,
    /// Parent block hash (32 bytes)
    pub parent_hash: [u8; 32],
    /// Ommers/uncles hash (always empty hash in PoS)
    pub ommers_hash: [u8; 32],
    /// Beneficiary/coinbase address (validator address or zero)
    pub beneficiary: [u8; 20],
    /// State root
    pub state_root: [u8; 32],
    /// Transactions root
    pub transactions_root: [u8; 32],
    /// Receipts root
    pub receipts_root: [u8; 32],
    /// Logs bloom filter (256 bytes)
    pub logs_bloom: Vec<u8>,
    /// Difficulty (always zero in PoS)
    pub difficulty: [u8; 32],
    /// Gas limit
    pub gas_limit: u64,
    /// Gas used
    pub gas_used: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Extra data
    pub extra_data: Vec<u8>,
    /// Mix hash (prevrandao in PoS)
    pub mix_hash: [u8; 32],
    /// Nonce (always zero in PoS)
    pub nonce: [u8; 8],
    /// Base fee per gas (EIP-1559)
    pub base_fee_per_gas: Option<u64>,
    /// Transaction hashes in this block (for eth_getBlockByNumber with full=false)
    pub transaction_hashes: Vec<[u8; 32]>,
    /// Transaction count
    pub transaction_count: u32,
    /// Total difficulty (not used in PoS, kept for compatibility)
    pub total_difficulty: [u8; 32],
    /// Block size in bytes (RLP-encoded size estimate)
    pub size: u64,
}

impl Block {
    /// Calculate the RLP-encoded block size in bytes.
    ///
    /// This computes the exact size of the block header when RLP-encoded,
    /// matching Ethereum's `size` field in block responses. We construct
    /// an `alloy_consensus::Header` from our block fields and use its
    /// `Encodable::length()` method to get the precise byte count.
    ///
    /// The Ethereum block `size` field represents the header size, not
    /// including the full transaction bodies (just transaction hashes
    /// contribute to transactions_root).
    pub fn calculate_size(&self) -> u64 {
        use alloy_consensus::Header;
        use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
        use alloy_rlp::Encodable;

        // Convert logs_bloom bytes to Bloom type
        let bloom = if self.logs_bloom.len() == 256 {
            let mut bloom_bytes = [0u8; 256];
            bloom_bytes.copy_from_slice(&self.logs_bloom);
            Bloom::from(bloom_bytes)
        } else {
            Bloom::ZERO
        };

        // Construct an alloy Header from our block fields
        let header = Header {
            parent_hash: B256::from(self.parent_hash),
            ommers_hash: B256::from(self.ommers_hash),
            beneficiary: Address::from(self.beneficiary),
            state_root: B256::from(self.state_root),
            transactions_root: B256::from(self.transactions_root),
            receipts_root: B256::from(self.receipts_root),
            logs_bloom: bloom,
            difficulty: U256::from_be_bytes(self.difficulty),
            number: self.number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: Bytes::copy_from_slice(&self.extra_data),
            mix_hash: B256::from(self.mix_hash),
            nonce: B64::from(self.nonce),
            base_fee_per_gas: self.base_fee_per_gas,
            // Post-merge fields (not used in our context, set to None)
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };

        // Get the exact RLP-encoded length
        header.length() as u64
    }
}

/// Trait for storing and retrieving blocks.
///
/// This trait provides async storage operations for blocks.
/// Blocks are indexed by block number (primary key) with a secondary index
/// by block hash for efficient hash-based queries.
///
/// Implementations must be thread-safe (`Send + Sync`) to support concurrent
/// access from multiple RPC handlers.
#[async_trait]
pub trait BlockStore: Send + Sync {
    /// Store a block.
    ///
    /// The block is stored using its number as the primary key.
    /// An entry is also added to the hash index.
    ///
    /// # Arguments
    /// * `block` - The block to store
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn put_block(&self, block: &Block) -> BlockStoreResult<()>;

    /// Retrieve a block by its number.
    ///
    /// # Arguments
    /// * `number` - Block number
    ///
    /// # Returns
    /// * `Ok(Some(block))` if the block exists
    /// * `Ok(None)` if the block does not exist
    /// * `Err(...)` if the storage operation fails
    async fn get_block_by_number(&self, number: u64) -> BlockStoreResult<Option<Block>>;

    /// Retrieve a block by its hash.
    ///
    /// # Arguments
    /// * `hash` - Block hash (32 bytes)
    ///
    /// # Returns
    /// * `Ok(Some(block))` if the block exists
    /// * `Ok(None)` if the block does not exist
    /// * `Err(...)` if the storage operation fails
    async fn get_block_by_hash(&self, hash: &[u8; 32]) -> BlockStoreResult<Option<Block>>;

    /// Get the block number for a given hash.
    ///
    /// This is a lightweight operation that does not deserialize the full block.
    ///
    /// # Arguments
    /// * `hash` - Block hash (32 bytes)
    ///
    /// # Returns
    /// * `Ok(Some(number))` if the block exists
    /// * `Ok(None)` if the block does not exist
    /// * `Err(...)` if the storage operation fails
    async fn get_block_number_by_hash(&self, hash: &[u8; 32]) -> BlockStoreResult<Option<u64>>;

    /// Get the latest block number.
    ///
    /// # Returns
    /// * `Ok(Some(number))` if any block exists
    /// * `Ok(None)` if no blocks exist
    /// * `Err(...)` if the storage operation fails
    async fn get_latest_block_number(&self) -> BlockStoreResult<Option<u64>>;

    /// Get the earliest block number.
    ///
    /// This returns the lowest block number stored in the database.
    /// For nodes that store the full chain, this will be 0 (genesis).
    /// For nodes with pruning enabled, this will be the oldest available block.
    ///
    /// # Returns
    /// * `Ok(Some(number))` if any block exists
    /// * `Ok(None)` if no blocks exist
    /// * `Err(...)` if the storage operation fails
    async fn get_earliest_block_number(&self) -> BlockStoreResult<Option<u64>>;

    /// Check if a block exists by number.
    ///
    /// This is a lightweight operation that does not deserialize the block.
    ///
    /// # Arguments
    /// * `number` - Block number
    ///
    /// # Returns
    /// * `Ok(true)` if the block exists
    /// * `Ok(false)` if the block does not exist
    /// * `Err(...)` if the storage operation fails
    async fn has_block(&self, number: u64) -> BlockStoreResult<bool>;

    /// Delete a block (for pruning).
    ///
    /// Removes the block with the given number from storage.
    /// Also removes the hash index entry.
    ///
    /// # Arguments
    /// * `number` - Block number to delete
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    /// Does not return an error if the block does not exist.
    async fn delete_block(&self, number: u64) -> BlockStoreResult<()>;
}
