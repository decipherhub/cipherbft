//! Trait definitions for RPC storage, mempool, execution, and network interfaces.
//!
//! These traits abstract the underlying implementations, enabling:
//! - Dependency injection for testing
//! - Swappable backends
//! - Clean separation between RPC layer and node internals

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types_eth::{Block, Filter, Log, Transaction, TransactionReceipt};
use async_trait::async_trait;

use crate::error::RpcResult;

/// Block number or tag for state queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockNumberOrTag {
    /// Specific block number.
    Number(u64),
    /// Latest finalized block.
    Latest,
    /// Earliest block (genesis).
    Earliest,
    /// Pending block (not yet finalized).
    Pending,
    /// Safe block (for PoS chains).
    Safe,
    /// Finalized block (for PoS chains).
    Finalized,
}

impl Default for BlockNumberOrTag {
    fn default() -> Self {
        Self::Latest
    }
}

impl From<u64> for BlockNumberOrTag {
    fn from(n: u64) -> Self {
        Self::Number(n)
    }
}

/// Sync status information.
#[derive(Debug, Clone)]
pub enum SyncStatus {
    /// Node is not syncing (fully synced).
    NotSyncing,
    /// Node is syncing.
    Syncing {
        /// Block number when sync started.
        starting_block: u64,
        /// Current block number.
        current_block: u64,
        /// Highest known block number.
        highest_block: u64,
    },
}

impl SyncStatus {
    /// Check if the node is syncing.
    pub fn is_syncing(&self) -> bool {
        matches!(self, Self::Syncing { .. })
    }
}

/// RPC storage interface for blockchain data queries.
#[async_trait]
pub trait RpcStorage: Send + Sync {
    /// Get a block by its number or tag.
    async fn get_block_by_number(
        &self,
        number: BlockNumberOrTag,
        full_transactions: bool,
    ) -> RpcResult<Option<Block>>;

    /// Get a block by its hash.
    async fn get_block_by_hash(
        &self,
        hash: B256,
        full_transactions: bool,
    ) -> RpcResult<Option<Block>>;

    /// Get a transaction by its hash.
    async fn get_transaction_by_hash(&self, hash: B256) -> RpcResult<Option<Transaction>>;

    /// Get a transaction receipt by transaction hash.
    async fn get_transaction_receipt(&self, hash: B256) -> RpcResult<Option<TransactionReceipt>>;

    /// Get logs matching the given filter.
    async fn get_logs(&self, filter: Filter) -> RpcResult<Vec<Log>>;

    /// Get the latest block number.
    async fn latest_block_number(&self) -> RpcResult<u64>;

    /// Get the sync status.
    async fn sync_status(&self) -> RpcResult<SyncStatus>;

    /// Get account balance at a specific block.
    async fn get_balance(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<U256>;

    /// Get contract bytecode at a specific block.
    async fn get_code(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<Bytes>;

    /// Get storage value at a specific slot and block.
    async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        block: BlockNumberOrTag,
    ) -> RpcResult<B256>;

    /// Get transaction count (nonce) for an address at a specific block.
    async fn get_transaction_count(
        &self,
        address: Address,
        block: BlockNumberOrTag,
    ) -> RpcResult<u64>;
}

/// Mempool interface for transaction submission.
#[async_trait]
pub trait MempoolApi: Send + Sync {
    /// Submit a raw signed transaction to the mempool.
    /// Returns the transaction hash on success.
    async fn submit_transaction(&self, tx_bytes: Bytes) -> RpcResult<B256>;

    /// Get pending transaction hashes from the mempool.
    async fn get_pending_transactions(&self) -> RpcResult<Vec<B256>>;
}

/// Execution interface for eth_call and gas estimation.
#[async_trait]
pub trait ExecutionApi: Send + Sync {
    /// Execute a read-only call against the state.
    async fn call(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        gas_price: Option<U256>,
        value: Option<U256>,
        data: Option<Bytes>,
        block: BlockNumberOrTag,
    ) -> RpcResult<Bytes>;

    /// Estimate gas for a transaction.
    async fn estimate_gas(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        gas_price: Option<U256>,
        value: Option<U256>,
        data: Option<Bytes>,
        block: BlockNumberOrTag,
    ) -> RpcResult<u64>;
}

/// Network interface for peer information.
#[async_trait]
pub trait NetworkApi: Send + Sync {
    /// Get the number of connected peers.
    async fn peer_count(&self) -> RpcResult<u64>;

    /// Check if the node is listening for connections.
    async fn is_listening(&self) -> RpcResult<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_number_or_tag() {
        let num: BlockNumberOrTag = 42.into();
        assert_eq!(num, BlockNumberOrTag::Number(42));

        let latest = BlockNumberOrTag::default();
        assert_eq!(latest, BlockNumberOrTag::Latest);
    }

    #[test]
    fn test_sync_status() {
        let not_syncing = SyncStatus::NotSyncing;
        assert!(!not_syncing.is_syncing());

        let syncing = SyncStatus::Syncing {
            starting_block: 0,
            current_block: 100,
            highest_block: 200,
        };
        assert!(syncing.is_syncing());
    }
}
