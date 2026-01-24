//! Storage adapter implementations for connecting RPC traits to CipherBFT storage.
//!
//! This module provides adapter implementations that bridge the RPC traits
//! (`RpcStorage`, `MempoolApi`, `ExecutionApi`, `NetworkApi`) to the actual
//! CipherBFT storage backends.
//!
//! # Architecture
//!
//! The adapters follow a layered approach:
//! - RPC handlers call trait methods on the adapters
//! - Adapters translate between RPC types (alloy) and storage types
//! - Actual storage backends (MDBX, in-memory) handle persistence
//!
//! # Adapter Types
//!
//! - `ProviderBasedRpcStorage`: Real adapter using execution layer's Provider trait
//! - `StubRpcStorage`: Placeholder for testing (block/transaction queries)
//! - `StubMempoolApi`: Placeholder until mempool integration
//! - `EvmExecutionApi`: Real execution adapter using revm (planned)
//! - `StubNetworkApi`: Placeholder until P2P integration

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types_eth::{Block, BlockTransactions, Filter, Header, Log, Transaction, TransactionReceipt};
use async_trait::async_trait;
use cipherbft_execution::database::Provider;
use cipherbft_mempool::pool::RecoveredTx;
use cipherbft_mempool::CipherBftPool;
use cipherbft_storage::mdbx::{MdbxBlockStore, MdbxReceiptStore};
use cipherbft_storage::{BlockStore, ReceiptStore};
use parking_lot::RwLock;
use reth_primitives::TransactionSigned;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, trace, warn};

use crate::error::{RpcError, RpcResult};
use crate::traits::{
    BlockNumberOrTag, ExecutionApi, MempoolApi, NetworkApi, RpcStorage, SyncStatus,
};

/// Provider-based RPC storage adapter.
///
/// This adapter uses the execution layer's `Provider` trait to answer
/// state queries (balance, code, storage, nonce). Block and transaction
/// queries are still stubbed until block indexing is implemented.
pub struct ProviderBasedRpcStorage<P: Provider> {
    /// The underlying provider for state queries.
    provider: Arc<P>,
    /// Chain ID for this network.
    /// Reserved for future use in eth_chainId responses.
    #[allow(dead_code)]
    chain_id: u64,
    /// Latest known block number (updated by consensus).
    latest_block: AtomicU64,
    /// Sync status tracking.
    sync_state: RwLock<SyncStateTracker>,
}

/// Internal sync state tracker.
#[derive(Debug, Clone, Default)]
struct SyncStateTracker {
    /// Whether we're currently syncing.
    is_syncing: bool,
    /// Block when sync started.
    starting_block: u64,
    /// Current block during sync.
    current_block: u64,
    /// Highest known block.
    highest_block: u64,
}

impl<P: Provider> ProviderBasedRpcStorage<P> {
    /// Create a new provider-based storage adapter.
    pub fn new(provider: Arc<P>, chain_id: u64) -> Self {
        Self {
            provider,
            chain_id,
            latest_block: AtomicU64::new(0),
            sync_state: RwLock::new(SyncStateTracker::default()),
        }
    }

    /// Update the latest block number (called by consensus layer).
    pub fn set_latest_block(&self, block: u64) {
        self.latest_block.store(block, Ordering::SeqCst);
    }

    /// Get the latest block number.
    pub fn get_latest_block(&self) -> u64 {
        self.latest_block.load(Ordering::SeqCst)
    }

    /// Update sync status (called by sync service).
    pub fn set_syncing(&self, starting: u64, current: u64, highest: u64) {
        let mut state = self.sync_state.write();
        state.is_syncing = true;
        state.starting_block = starting;
        state.current_block = current;
        state.highest_block = highest;
    }

    /// Mark sync as complete.
    pub fn set_synced(&self) {
        let mut state = self.sync_state.write();
        state.is_syncing = false;
    }

    /// Resolve block number from tag.
    fn resolve_block_number(&self, block: BlockNumberOrTag) -> u64 {
        match block {
            BlockNumberOrTag::Number(n) => n,
            BlockNumberOrTag::Latest
            | BlockNumberOrTag::Safe
            | BlockNumberOrTag::Finalized
            | BlockNumberOrTag::Pending => self.latest_block.load(Ordering::SeqCst),
            BlockNumberOrTag::Earliest => 0,
        }
    }
}

#[async_trait]
impl<P: Provider + 'static> RpcStorage for ProviderBasedRpcStorage<P> {
    async fn get_block_by_number(
        &self,
        number: BlockNumberOrTag,
        _full_transactions: bool,
    ) -> RpcResult<Option<Block>> {
        let resolved = self.resolve_block_number(number);
        trace!(
            "ProviderBasedRpcStorage::get_block_by_number({:?} -> {})",
            number,
            resolved
        );
        // Block indexing not yet implemented - return None
        // TODO: Implement when block storage is added
        Ok(None)
    }

    async fn get_block_by_hash(
        &self,
        hash: B256,
        _full_transactions: bool,
    ) -> RpcResult<Option<Block>> {
        trace!("ProviderBasedRpcStorage::get_block_by_hash({})", hash);
        // Block indexing not yet implemented - return None
        // TODO: Implement when block storage is added
        Ok(None)
    }

    async fn get_transaction_by_hash(&self, hash: B256) -> RpcResult<Option<Transaction>> {
        trace!("ProviderBasedRpcStorage::get_transaction_by_hash({})", hash);
        // Transaction indexing not yet implemented - return None
        // TODO: Implement when transaction storage is added
        Ok(None)
    }

    async fn get_transaction_receipt(&self, hash: B256) -> RpcResult<Option<TransactionReceipt>> {
        trace!("ProviderBasedRpcStorage::get_transaction_receipt({})", hash);
        // Receipt storage not yet implemented - return None
        // TODO: Implement when receipt storage is added
        Ok(None)
    }

    async fn get_logs(&self, filter: Filter) -> RpcResult<Vec<Log>> {
        trace!("ProviderBasedRpcStorage::get_logs({:?})", filter);
        // Log indexing not yet implemented - return empty
        // TODO: Implement when log indexing is added
        Ok(Vec::new())
    }

    async fn latest_block_number(&self) -> RpcResult<u64> {
        trace!("ProviderBasedRpcStorage::latest_block_number");
        Ok(self.latest_block.load(Ordering::SeqCst))
    }

    async fn sync_status(&self) -> RpcResult<SyncStatus> {
        trace!("ProviderBasedRpcStorage::sync_status");
        let state = self.sync_state.read();
        if state.is_syncing {
            Ok(SyncStatus::Syncing {
                starting_block: state.starting_block,
                current_block: state.current_block,
                highest_block: state.highest_block,
            })
        } else {
            Ok(SyncStatus::NotSyncing)
        }
    }

    async fn get_balance(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<U256> {
        let _block_num = self.resolve_block_number(block);
        trace!(
            "ProviderBasedRpcStorage::get_balance({}, {:?})",
            address,
            block
        );

        // Query account from provider
        // Note: Currently queries latest state; historical state requires state archival
        match self.provider.get_account(address) {
            Ok(Some(account)) => {
                debug!("Found account {} with balance {}", address, account.balance);
                Ok(account.balance)
            }
            Ok(None) => {
                trace!("Account {} not found, returning zero balance", address);
                Ok(U256::ZERO)
            }
            Err(e) => {
                debug!("Error getting account {}: {}", address, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_code(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<Bytes> {
        let _block_num = self.resolve_block_number(block);
        trace!(
            "ProviderBasedRpcStorage::get_code({}, {:?})",
            address,
            block
        );

        // First get account to find code hash
        match self.provider.get_account(address) {
            Ok(Some(account)) => {
                // Check if account has code (not KECCAK_EMPTY)
                let keccak_empty = B256::from(cipherbft_execution::KECCAK_EMPTY);
                if account.code_hash == keccak_empty || account.code_hash == B256::ZERO {
                    trace!("Account {} has no code", address);
                    return Ok(Bytes::new());
                }

                // Get the actual bytecode
                match self.provider.get_code(account.code_hash) {
                    Ok(Some(bytecode)) => {
                        let bytes = bytecode.bytes_slice().to_vec();
                        debug!("Found code for {} ({} bytes)", address, bytes.len());
                        Ok(Bytes::from(bytes))
                    }
                    Ok(None) => {
                        trace!("Code hash {} not found for {}", account.code_hash, address);
                        Ok(Bytes::new())
                    }
                    Err(e) => {
                        debug!("Error getting code for {}: {}", address, e);
                        Err(RpcError::Storage(e.to_string()))
                    }
                }
            }
            Ok(None) => {
                trace!("Account {} not found", address);
                Ok(Bytes::new())
            }
            Err(e) => {
                debug!("Error getting account {}: {}", address, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        block: BlockNumberOrTag,
    ) -> RpcResult<B256> {
        let _block_num = self.resolve_block_number(block);
        trace!(
            "ProviderBasedRpcStorage::get_storage_at({}, {}, {:?})",
            address,
            slot,
            block
        );

        match self.provider.get_storage(address, slot) {
            Ok(value) => {
                let result = B256::from(value.to_be_bytes::<32>());
                if !value.is_zero() {
                    debug!("Found storage {}[{}] = {}", address, slot, value);
                }
                Ok(result)
            }
            Err(e) => {
                debug!("Error getting storage {}[{}]: {}", address, slot, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_transaction_count(
        &self,
        address: Address,
        block: BlockNumberOrTag,
    ) -> RpcResult<u64> {
        let _block_num = self.resolve_block_number(block);
        trace!(
            "ProviderBasedRpcStorage::get_transaction_count({}, {:?})",
            address,
            block
        );

        match self.provider.get_account(address) {
            Ok(Some(account)) => {
                debug!("Found account {} with nonce {}", address, account.nonce);
                Ok(account.nonce)
            }
            Ok(None) => {
                trace!("Account {} not found, returning nonce 0", address);
                Ok(0)
            }
            Err(e) => {
                debug!("Error getting account {}: {}", address, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }
}

// ============================================================================
// MDBX-backed RPC Storage Implementation
// ============================================================================

/// MDBX-backed RPC storage that uses real block and receipt stores.
///
/// This adapter combines the execution layer's `Provider` trait for state queries
/// with MDBX-backed block and receipt stores for historical data. It bridges the
/// gap between the RPC interface and the persistent storage layer.
///
/// # Architecture
///
/// - State queries (balance, code, storage, nonce): Delegated to the `Provider`
/// - Block queries: Use `MdbxBlockStore`
/// - Receipt queries: Use `MdbxReceiptStore`
/// - Latest block tracking: Managed internally via `AtomicU64`
///
/// # Thread Safety
///
/// This type is thread-safe and can be shared across threads using `Arc`.
/// The underlying MDBX database handles concurrent access.
pub struct MdbxRpcStorage<P: Provider> {
    /// Provider for state queries (balance, code, storage, nonce).
    provider: Arc<P>,
    /// Block storage.
    block_store: Arc<MdbxBlockStore>,
    /// Receipt storage.
    receipt_store: Arc<MdbxReceiptStore>,
    /// Chain ID.
    chain_id: u64,
    /// Latest block number (updated by consensus).
    latest_block: AtomicU64,
}

impl<P: Provider> MdbxRpcStorage<P> {
    /// Create new MDBX-backed RPC storage.
    ///
    /// # Arguments
    ///
    /// * `provider` - Provider for state queries
    /// * `block_store` - MDBX-backed block store
    /// * `receipt_store` - MDBX-backed receipt store
    /// * `chain_id` - Chain ID for this network
    pub fn new(
        provider: Arc<P>,
        block_store: Arc<MdbxBlockStore>,
        receipt_store: Arc<MdbxReceiptStore>,
        chain_id: u64,
    ) -> Self {
        Self {
            provider,
            block_store,
            receipt_store,
            chain_id,
            latest_block: AtomicU64::new(0),
        }
    }

    /// Update the latest block number.
    ///
    /// This should be called by the consensus layer when a new block is finalized.
    pub fn set_latest_block(&self, block: u64) {
        self.latest_block.store(block, Ordering::SeqCst);
    }

    /// Get the latest block number.
    pub fn latest_block(&self) -> u64 {
        self.latest_block.load(Ordering::SeqCst)
    }

    /// Get reference to block store.
    pub fn block_store(&self) -> &Arc<MdbxBlockStore> {
        &self.block_store
    }

    /// Get reference to receipt store.
    pub fn receipt_store(&self) -> &Arc<MdbxReceiptStore> {
        &self.receipt_store
    }

    /// Get reference to provider.
    pub fn provider(&self) -> &Arc<P> {
        &self.provider
    }

    /// Get chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Resolve block number from tag.
    ///
    /// For `Latest`, `Safe`, `Finalized`, `Pending`: returns `self.latest_block()`
    /// For `Earliest`: returns 0 (genesis)
    /// For `Number(n)`: returns `n`
    fn resolve_block_number(&self, tag: BlockNumberOrTag) -> u64 {
        match tag {
            BlockNumberOrTag::Number(n) => n,
            BlockNumberOrTag::Latest
            | BlockNumberOrTag::Safe
            | BlockNumberOrTag::Finalized
            | BlockNumberOrTag::Pending => self.latest_block.load(Ordering::SeqCst),
            BlockNumberOrTag::Earliest => 0,
        }
    }

    /// Convert a storage block to an RPC block.
    ///
    /// # Arguments
    ///
    /// * `storage_block` - The block from storage
    /// * `full_txs` - If true, include full transaction objects; otherwise just hashes
    ///
    /// # Returns
    ///
    /// An RPC Block suitable for JSON-RPC responses.
    fn storage_block_to_rpc(
        &self,
        storage_block: cipherbft_storage::blocks::Block,
        full_txs: bool,
    ) -> Block {
        use alloy_primitives::{Bloom, B64};

        // Convert transaction hashes to B256
        let tx_hashes: Vec<B256> = storage_block
            .transaction_hashes
            .iter()
            .map(|h| B256::from(*h))
            .collect();

        // Build transactions field based on full_txs flag
        // For now, we only support returning hashes (full tx bodies will come later)
        let transactions = if full_txs {
            // TODO: In the future, this should return full Transaction objects
            // For now, return hashes even when full_txs is true
            BlockTransactions::Hashes(tx_hashes)
        } else {
            BlockTransactions::Hashes(tx_hashes)
        };

        // Build the consensus header
        let consensus_header = alloy_consensus::Header {
            parent_hash: B256::from(storage_block.parent_hash),
            ommers_hash: B256::from(storage_block.ommers_hash),
            beneficiary: Address::from(storage_block.beneficiary),
            state_root: B256::from(storage_block.state_root),
            transactions_root: B256::from(storage_block.transactions_root),
            receipts_root: B256::from(storage_block.receipts_root),
            logs_bloom: Bloom::from_slice(&storage_block.logs_bloom),
            difficulty: U256::from_be_bytes(storage_block.difficulty),
            number: storage_block.number,
            gas_limit: storage_block.gas_limit,
            gas_used: storage_block.gas_used,
            timestamp: storage_block.timestamp,
            extra_data: Bytes::from(storage_block.extra_data),
            mix_hash: B256::from(storage_block.mix_hash),
            nonce: B64::from(storage_block.nonce),
            base_fee_per_gas: storage_block.base_fee_per_gas,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };

        // Build the RPC header with hash and total difficulty
        let block_hash = B256::from(storage_block.hash);
        let total_difficulty = U256::from_be_bytes(storage_block.total_difficulty);

        let rpc_header = Header {
            hash: block_hash,
            inner: consensus_header,
            total_difficulty: Some(total_difficulty),
            size: None,
        };

        // Build the final RPC block
        Block {
            header: rpc_header,
            uncles: Vec::new(),
            transactions,
            withdrawals: None,
        }
    }

    /// Convert a storage receipt to an RPC transaction receipt.
    fn storage_receipt_to_rpc(
        &self,
        storage_receipt: cipherbft_storage::receipts::Receipt,
    ) -> TransactionReceipt {
        use alloy_consensus::{Eip658Value, ReceiptEnvelope};

        // Convert logs to RPC format
        let logs: Vec<Log> = storage_receipt
            .logs
            .iter()
            .enumerate()
            .map(|(idx, storage_log)| {
                Log {
                    inner: alloy_primitives::Log {
                        address: Address::from(storage_log.address),
                        data: alloy_primitives::LogData::new(
                            storage_log.topics.iter().map(|t| B256::from(*t)).collect(),
                            Bytes::from(storage_log.data.clone()),
                        )
                        .unwrap_or_default(),
                    },
                    block_hash: Some(B256::from(storage_receipt.block_hash)),
                    block_number: Some(storage_receipt.block_number),
                    block_timestamp: None,
                    transaction_hash: Some(B256::from(storage_receipt.transaction_hash)),
                    transaction_index: Some(storage_receipt.transaction_index as u64),
                    log_index: Some(idx as u64),
                    removed: false,
                }
            })
            .collect();

        // Build receipt with logs
        let inner_receipt = alloy_consensus::Receipt {
            status: Eip658Value::Eip658(storage_receipt.status),
            cumulative_gas_used: storage_receipt.cumulative_gas_used,
            logs: logs.clone(),
        };

        // Create bloom from logs
        let receipt_with_bloom = inner_receipt.with_bloom();

        // Build receipt envelope based on transaction type
        let receipt_envelope: ReceiptEnvelope<Log> = match storage_receipt.transaction_type {
            0 => ReceiptEnvelope::Legacy(receipt_with_bloom),
            1 => ReceiptEnvelope::Eip2930(receipt_with_bloom),
            2 => ReceiptEnvelope::Eip1559(receipt_with_bloom),
            _ => ReceiptEnvelope::Legacy(receipt_with_bloom),
        };

        TransactionReceipt {
            inner: receipt_envelope,
            transaction_hash: B256::from(storage_receipt.transaction_hash),
            transaction_index: Some(storage_receipt.transaction_index as u64),
            block_hash: Some(B256::from(storage_receipt.block_hash)),
            block_number: Some(storage_receipt.block_number),
            gas_used: storage_receipt.gas_used,
            effective_gas_price: storage_receipt.effective_gas_price as u128,
            blob_gas_used: None,
            blob_gas_price: None,
            from: Address::from(storage_receipt.from),
            to: storage_receipt.to.map(Address::from),
            contract_address: storage_receipt.contract_address.map(Address::from),
        }
    }
}

#[async_trait]
impl<P: Provider + 'static> RpcStorage for MdbxRpcStorage<P> {
    async fn get_block_by_number(
        &self,
        number: BlockNumberOrTag,
        full_transactions: bool,
    ) -> RpcResult<Option<Block>> {
        let resolved = self.resolve_block_number(number);
        trace!(
            "MdbxRpcStorage::get_block_by_number({:?} -> {})",
            number,
            resolved
        );

        // Query the block store
        match self.block_store.get_block_by_number(resolved).await {
            Ok(Some(storage_block)) => {
                debug!("Found block {} with hash {:?}", resolved, storage_block.hash);
                let rpc_block = self.storage_block_to_rpc(storage_block, full_transactions);
                Ok(Some(rpc_block))
            }
            Ok(None) => {
                trace!("Block {} not found", resolved);
                Ok(None)
            }
            Err(e) => {
                debug!("Error getting block {}: {}", resolved, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_block_by_hash(
        &self,
        hash: B256,
        full_transactions: bool,
    ) -> RpcResult<Option<Block>> {
        trace!("MdbxRpcStorage::get_block_by_hash({})", hash);

        let hash_bytes: [u8; 32] = hash.into();

        // Query the block store
        match self.block_store.get_block_by_hash(&hash_bytes).await {
            Ok(Some(storage_block)) => {
                debug!(
                    "Found block {} with hash {}",
                    storage_block.number,
                    hash
                );
                let rpc_block = self.storage_block_to_rpc(storage_block, full_transactions);
                Ok(Some(rpc_block))
            }
            Ok(None) => {
                trace!("Block with hash {} not found", hash);
                Ok(None)
            }
            Err(e) => {
                debug!("Error getting block by hash {}: {}", hash, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_transaction_by_hash(&self, hash: B256) -> RpcResult<Option<Transaction>> {
        trace!("MdbxRpcStorage::get_transaction_by_hash({})", hash);
        // Transaction indexing not yet implemented - return None
        // TODO: Implement when transaction storage is added
        Ok(None)
    }

    async fn get_transaction_receipt(&self, hash: B256) -> RpcResult<Option<TransactionReceipt>> {
        trace!("MdbxRpcStorage::get_transaction_receipt({})", hash);

        let hash_bytes: [u8; 32] = hash.into();

        // Query the receipt store
        match self.receipt_store.get_receipt(&hash_bytes).await {
            Ok(Some(storage_receipt)) => {
                debug!(
                    "Found receipt for tx {} in block {}",
                    hash, storage_receipt.block_number
                );
                let rpc_receipt = self.storage_receipt_to_rpc(storage_receipt);
                Ok(Some(rpc_receipt))
            }
            Ok(None) => {
                trace!("Receipt for tx {} not found", hash);
                Ok(None)
            }
            Err(e) => {
                debug!("Error getting receipt for tx {}: {}", hash, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_logs(&self, filter: Filter) -> RpcResult<Vec<Log>> {
        trace!("MdbxRpcStorage::get_logs({:?})", filter);
        // Log indexing not yet implemented - return empty
        // TODO: Implement when log indexing is added
        Ok(Vec::new())
    }

    async fn latest_block_number(&self) -> RpcResult<u64> {
        trace!("MdbxRpcStorage::latest_block_number");
        Ok(self.latest_block.load(Ordering::SeqCst))
    }

    async fn sync_status(&self) -> RpcResult<SyncStatus> {
        trace!("MdbxRpcStorage::sync_status");
        // For now, always return not syncing
        // TODO: Add sync status tracking similar to ProviderBasedRpcStorage
        Ok(SyncStatus::NotSyncing)
    }

    async fn get_balance(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<U256> {
        let _block_num = self.resolve_block_number(block);
        trace!(
            "MdbxRpcStorage::get_balance({}, {:?})",
            address,
            block
        );

        // Query account from provider
        // Note: Currently queries latest state; historical state requires state archival
        match self.provider.get_account(address) {
            Ok(Some(account)) => {
                debug!("Found account {} with balance {}", address, account.balance);
                Ok(account.balance)
            }
            Ok(None) => {
                trace!("Account {} not found, returning zero balance", address);
                Ok(U256::ZERO)
            }
            Err(e) => {
                debug!("Error getting account {}: {}", address, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_code(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<Bytes> {
        let _block_num = self.resolve_block_number(block);
        trace!(
            "MdbxRpcStorage::get_code({}, {:?})",
            address,
            block
        );

        // First get account to find code hash
        match self.provider.get_account(address) {
            Ok(Some(account)) => {
                // Check if account has code (not KECCAK_EMPTY)
                let keccak_empty = B256::from(cipherbft_execution::KECCAK_EMPTY);
                if account.code_hash == keccak_empty || account.code_hash == B256::ZERO {
                    trace!("Account {} has no code", address);
                    return Ok(Bytes::new());
                }

                // Get the actual bytecode
                match self.provider.get_code(account.code_hash) {
                    Ok(Some(bytecode)) => {
                        let bytes = bytecode.bytes_slice().to_vec();
                        debug!("Found code for {} ({} bytes)", address, bytes.len());
                        Ok(Bytes::from(bytes))
                    }
                    Ok(None) => {
                        trace!("Code hash {} not found for {}", account.code_hash, address);
                        Ok(Bytes::new())
                    }
                    Err(e) => {
                        debug!("Error getting code for {}: {}", address, e);
                        Err(RpcError::Storage(e.to_string()))
                    }
                }
            }
            Ok(None) => {
                trace!("Account {} not found", address);
                Ok(Bytes::new())
            }
            Err(e) => {
                debug!("Error getting account {}: {}", address, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        block: BlockNumberOrTag,
    ) -> RpcResult<B256> {
        let _block_num = self.resolve_block_number(block);
        trace!(
            "MdbxRpcStorage::get_storage_at({}, {}, {:?})",
            address,
            slot,
            block
        );

        match self.provider.get_storage(address, slot) {
            Ok(value) => {
                let result = B256::from(value.to_be_bytes::<32>());
                if !value.is_zero() {
                    debug!("Found storage {}[{}] = {}", address, slot, value);
                }
                Ok(result)
            }
            Err(e) => {
                debug!("Error getting storage {}[{}]: {}", address, slot, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_transaction_count(
        &self,
        address: Address,
        block: BlockNumberOrTag,
    ) -> RpcResult<u64> {
        let _block_num = self.resolve_block_number(block);
        trace!(
            "MdbxRpcStorage::get_transaction_count({}, {:?})",
            address,
            block
        );

        match self.provider.get_account(address) {
            Ok(Some(account)) => {
                debug!("Found account {} with nonce {}", address, account.nonce);
                Ok(account.nonce)
            }
            Ok(None) => {
                trace!("Account {} not found, returning nonce 0", address);
                Ok(0)
            }
            Err(e) => {
                debug!("Error getting account {}: {}", address, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }
}

// ============================================================================
// Stub Implementations (for testing and features not yet integrated)
// ============================================================================

/// Stub RPC storage adapter.
///
/// This adapter provides placeholder implementations for RPC storage operations.
/// Used for testing or when the real storage backend is not available.
///
/// Uses `AtomicU64` for `latest_block` to allow thread-safe updates from the
/// consensus event loop while the storage is behind an `Arc`.
pub struct StubRpcStorage {
    /// Latest block number (atomic for thread-safe updates).
    latest_block: AtomicU64,
    /// Chain ID (reserved for future use).
    #[allow(dead_code)]
    chain_id: u64,
}

impl StubRpcStorage {
    /// Create a new stub storage adapter.
    pub fn new(chain_id: u64) -> Self {
        Self {
            latest_block: AtomicU64::new(0),
            chain_id,
        }
    }

    /// Set the latest block number.
    ///
    /// Thread-safe: can be called from the consensus event loop while
    /// the storage is behind an `Arc`.
    pub fn set_latest_block(&self, block: u64) {
        self.latest_block.store(block, Ordering::SeqCst);
    }
}

impl Default for StubRpcStorage {
    fn default() -> Self {
        Self::new(85300) // CipherBFT testnet chain ID
    }
}

#[async_trait]
impl RpcStorage for StubRpcStorage {
    async fn get_block_by_number(
        &self,
        number: BlockNumberOrTag,
        _full_transactions: bool,
    ) -> RpcResult<Option<Block>> {
        trace!("StubRpcStorage::get_block_by_number({:?})", number);
        Ok(None)
    }

    async fn get_block_by_hash(
        &self,
        hash: B256,
        _full_transactions: bool,
    ) -> RpcResult<Option<Block>> {
        trace!("StubRpcStorage::get_block_by_hash({})", hash);
        Ok(None)
    }

    async fn get_transaction_by_hash(&self, hash: B256) -> RpcResult<Option<Transaction>> {
        trace!("StubRpcStorage::get_transaction_by_hash({})", hash);
        Ok(None)
    }

    async fn get_transaction_receipt(&self, hash: B256) -> RpcResult<Option<TransactionReceipt>> {
        trace!("StubRpcStorage::get_transaction_receipt({})", hash);
        Ok(None)
    }

    async fn get_logs(&self, filter: Filter) -> RpcResult<Vec<Log>> {
        trace!("StubRpcStorage::get_logs({:?})", filter);
        Ok(Vec::new())
    }

    async fn latest_block_number(&self) -> RpcResult<u64> {
        trace!("StubRpcStorage::latest_block_number");
        Ok(self.latest_block.load(Ordering::SeqCst))
    }

    async fn sync_status(&self) -> RpcResult<SyncStatus> {
        trace!("StubRpcStorage::sync_status");
        Ok(SyncStatus::NotSyncing)
    }

    async fn get_balance(&self, address: Address, _block: BlockNumberOrTag) -> RpcResult<U256> {
        trace!("StubRpcStorage::get_balance({})", address);
        Ok(U256::ZERO)
    }

    async fn get_code(&self, address: Address, _block: BlockNumberOrTag) -> RpcResult<Bytes> {
        trace!("StubRpcStorage::get_code({})", address);
        Ok(Bytes::new())
    }

    async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        _block: BlockNumberOrTag,
    ) -> RpcResult<B256> {
        trace!("StubRpcStorage::get_storage_at({}, {})", address, slot);
        Ok(B256::ZERO)
    }

    async fn get_transaction_count(
        &self,
        address: Address,
        _block: BlockNumberOrTag,
    ) -> RpcResult<u64> {
        trace!("StubRpcStorage::get_transaction_count({})", address);
        Ok(0)
    }
}

/// Stub mempool adapter.
///
/// This adapter provides placeholder implementations for mempool operations.
/// Replace with actual mempool integration when ready.
pub struct StubMempoolApi;

impl StubMempoolApi {
    /// Create a new stub mempool adapter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for StubMempoolApi {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MempoolApi for StubMempoolApi {
    async fn submit_transaction(&self, tx_bytes: Bytes) -> RpcResult<B256> {
        debug!(
            "StubMempoolApi::submit_transaction({} bytes)",
            tx_bytes.len()
        );
        // For stub: compute a hash from the transaction bytes
        // In production, this would submit to actual mempool and return the tx hash
        let hash = alloy_primitives::keccak256(&tx_bytes);
        Ok(hash)
    }

    async fn get_pending_transactions(&self) -> RpcResult<Vec<B256>> {
        trace!("StubMempoolApi::get_pending_transactions");
        Ok(Vec::new())
    }

    async fn get_transaction_by_hash(&self, hash: B256) -> RpcResult<Option<Transaction>> {
        trace!("StubMempoolApi::get_transaction_by_hash({})", hash);
        // Stub implementation: no transactions in mempool
        Ok(None)
    }

    async fn get_pool_status(&self) -> RpcResult<(usize, usize)> {
        trace!("StubMempoolApi::get_pool_status");
        Ok((0, 0))
    }

    async fn get_pending_content(
        &self,
    ) -> RpcResult<std::collections::HashMap<Address, Vec<Transaction>>> {
        trace!("StubMempoolApi::get_pending_content");
        Ok(std::collections::HashMap::new())
    }

    async fn get_queued_content(
        &self,
    ) -> RpcResult<std::collections::HashMap<Address, Vec<Transaction>>> {
        trace!("StubMempoolApi::get_queued_content");
        Ok(std::collections::HashMap::new())
    }
}

/// Convert a signed transaction to an RPC Transaction.
///
/// For pending (mempool) transactions, block-related fields are None since
/// the transaction hasn't been included in a block yet.
fn signed_tx_to_rpc_tx(signed_tx: &TransactionSigned, sender: Address) -> Transaction {
    use alloy_consensus::Transaction as ConsensusTx;
    use reth_primitives_traits::Recovered;

    let hash = *signed_tx.tx_hash();
    let signature = *signed_tx.signature();

    // Convert reth TransactionSigned to alloy TxEnvelope
    // We need to match on the transaction type and convert accordingly
    let tx_envelope: alloy_consensus::TxEnvelope = match signed_tx.tx_type() as u8 {
        0 => {
            // Legacy transaction
            let legacy = alloy_consensus::TxLegacy {
                chain_id: signed_tx.chain_id(),
                nonce: signed_tx.nonce(),
                gas_price: signed_tx.max_fee_per_gas() as u128,
                gas_limit: signed_tx.gas_limit(),
                to: signed_tx.to().into(),
                value: signed_tx.value(),
                input: signed_tx.input().clone(),
            };
            alloy_consensus::TxEnvelope::Legacy(alloy_consensus::Signed::new_unchecked(
                legacy, signature, hash,
            ))
        }
        1 => {
            // EIP-2930 transaction
            let eip2930 = alloy_consensus::TxEip2930 {
                chain_id: signed_tx.chain_id().unwrap_or(1),
                nonce: signed_tx.nonce(),
                gas_price: signed_tx.max_fee_per_gas() as u128,
                gas_limit: signed_tx.gas_limit(),
                to: signed_tx.to().into(),
                value: signed_tx.value(),
                input: signed_tx.input().clone(),
                access_list: Default::default(), // TODO: extract from tx
            };
            alloy_consensus::TxEnvelope::Eip2930(alloy_consensus::Signed::new_unchecked(
                eip2930, signature, hash,
            ))
        }
        2 => {
            // EIP-1559 transaction
            let eip1559 = alloy_consensus::TxEip1559 {
                chain_id: signed_tx.chain_id().unwrap_or(1),
                nonce: signed_tx.nonce(),
                max_fee_per_gas: signed_tx.max_fee_per_gas() as u128,
                max_priority_fee_per_gas: signed_tx.max_priority_fee_per_gas().unwrap_or(0) as u128,
                gas_limit: signed_tx.gas_limit(),
                to: signed_tx.to().into(),
                value: signed_tx.value(),
                input: signed_tx.input().clone(),
                access_list: Default::default(), // TODO: extract from tx
            };
            alloy_consensus::TxEnvelope::Eip1559(alloy_consensus::Signed::new_unchecked(
                eip1559, signature, hash,
            ))
        }
        _ => {
            // Default to legacy for unknown types
            let legacy = alloy_consensus::TxLegacy {
                chain_id: signed_tx.chain_id(),
                nonce: signed_tx.nonce(),
                gas_price: signed_tx.max_fee_per_gas() as u128,
                gas_limit: signed_tx.gas_limit(),
                to: signed_tx.to().into(),
                value: signed_tx.value(),
                input: signed_tx.input().clone(),
            };
            alloy_consensus::TxEnvelope::Legacy(alloy_consensus::Signed::new_unchecked(
                legacy, signature, hash,
            ))
        }
    };

    // Wrap in Recovered to include sender
    let recovered = Recovered::new_unchecked(tx_envelope, sender);

    // Build the RPC transaction
    // For pending transactions, block-related fields are None
    Transaction {
        inner: recovered,
        block_hash: None,
        block_number: None,
        transaction_index: None,
        effective_gas_price: None,
    }
}

/// Real mempool adapter backed by CipherBftPool.
///
/// This adapter implements the MempoolApi trait using an actual transaction pool.
/// It wraps a `CipherBftPool` and delegates transaction submission and queries
/// to the underlying pool.
pub struct PoolMempoolApi<P: TransactionPool> {
    /// The underlying CipherBFT transaction pool.
    pool: Arc<CipherBftPool<P>>,
}

impl<P: TransactionPool> PoolMempoolApi<P> {
    /// Create a new mempool adapter wrapping a CipherBftPool.
    pub fn new(pool: Arc<CipherBftPool<P>>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl<P> MempoolApi for PoolMempoolApi<P>
where
    P: TransactionPool + Send + Sync + 'static,
    P::Transaction: PoolTransaction<Consensus = TransactionSigned> + TryFrom<RecoveredTx>,
    <P::Transaction as TryFrom<RecoveredTx>>::Error: std::fmt::Display,
{
    async fn submit_transaction(&self, tx_bytes: Bytes) -> RpcResult<B256> {
        debug!(
            "PoolMempoolApi::submit_transaction({} bytes)",
            tx_bytes.len()
        );

        // Decode the transaction to get its hash
        use alloy_rlp::Decodable;
        let tx = TransactionSigned::decode(&mut tx_bytes.as_ref()).map_err(|e| {
            warn!("Failed to decode transaction: {}", e);
            RpcError::InvalidParams(format!("Invalid transaction encoding: {e}"))
        })?;

        // Get the transaction hash before submitting
        let tx_hash = *tx.tx_hash();

        // Submit to the pool
        self.pool
            .add_signed_transaction(TransactionOrigin::External, tx)
            .await
            .map_err(|e| {
                warn!("Failed to submit transaction: {}", e);
                RpcError::Execution(format!("Transaction submission failed: {e}"))
            })?;

        debug!("Transaction submitted successfully: {}", tx_hash);
        Ok(tx_hash)
    }

    async fn get_pending_transactions(&self) -> RpcResult<Vec<B256>> {
        trace!("PoolMempoolApi::get_pending_transactions");

        // Get all transaction hashes from the pool (pending + queued)
        let all_txs = self.pool.pool().all_transactions();
        let hashes: Vec<B256> = all_txs
            .pending
            .iter()
            .chain(all_txs.queued.iter())
            .map(|tx| *tx.hash())
            .collect();

        debug!("Found {} transactions in pool", hashes.len());
        Ok(hashes)
    }

    async fn get_transaction_by_hash(&self, hash: B256) -> RpcResult<Option<Transaction>> {
        trace!("PoolMempoolApi::get_transaction_by_hash({})", hash);

        // Search through all transactions in the pool
        let all_txs = self.pool.pool().all_transactions();

        // Search in both pending and queued pools
        let maybe_tx = all_txs
            .pending
            .iter()
            .chain(all_txs.queued.iter())
            .find(|tx| *tx.hash() == hash);

        match maybe_tx {
            Some(pool_tx) => {
                // Convert pool transaction to RPC Transaction
                let signed_tx = pool_tx.transaction.clone_into_consensus().into_inner();
                let rpc_tx = signed_tx_to_rpc_tx(&signed_tx, pool_tx.sender());
                debug!("Found transaction {} in mempool", hash);
                Ok(Some(rpc_tx))
            }
            None => {
                trace!("Transaction {} not found in mempool", hash);
                Ok(None)
            }
        }
    }

    async fn get_pool_status(&self) -> RpcResult<(usize, usize)> {
        trace!("PoolMempoolApi::get_pool_status");

        let all_txs = self.pool.pool().all_transactions();
        let pending_count = all_txs.pending.len();
        let queued_count = all_txs.queued.len();

        debug!(
            "Pool status: {} pending, {} queued",
            pending_count, queued_count
        );
        Ok((pending_count, queued_count))
    }

    async fn get_pending_content(
        &self,
    ) -> RpcResult<std::collections::HashMap<Address, Vec<Transaction>>> {
        trace!("PoolMempoolApi::get_pending_content");

        let all_txs = self.pool.pool().all_transactions();
        let mut result: std::collections::HashMap<Address, Vec<Transaction>> =
            std::collections::HashMap::new();

        for pool_tx in all_txs.pending {
            let sender = pool_tx.sender();
            let signed_tx = pool_tx.transaction.clone_into_consensus().into_inner();
            let rpc_tx = signed_tx_to_rpc_tx(&signed_tx, sender);

            result.entry(sender).or_default().push(rpc_tx);
        }

        debug!("Pending content: {} senders", result.len());
        Ok(result)
    }

    async fn get_queued_content(
        &self,
    ) -> RpcResult<std::collections::HashMap<Address, Vec<Transaction>>> {
        trace!("PoolMempoolApi::get_queued_content");

        let all_txs = self.pool.pool().all_transactions();
        let mut result: std::collections::HashMap<Address, Vec<Transaction>> =
            std::collections::HashMap::new();

        for pool_tx in all_txs.queued {
            let sender = pool_tx.sender();
            let signed_tx = pool_tx.transaction.clone_into_consensus().into_inner();
            let rpc_tx = signed_tx_to_rpc_tx(&signed_tx, sender);

            result.entry(sender).or_default().push(rpc_tx);
        }

        debug!("Queued content: {} senders", result.len());
        Ok(result)
    }
}

/// Stub execution adapter.
///
/// This adapter provides placeholder implementations for execution operations.
/// Replace with actual revm execution integration when ready.
pub struct StubExecutionApi;

impl StubExecutionApi {
    /// Create a new stub execution adapter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for StubExecutionApi {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ExecutionApi for StubExecutionApi {
    async fn call(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        _gas_price: Option<U256>,
        _value: Option<U256>,
        data: Option<Bytes>,
        _block: BlockNumberOrTag,
    ) -> RpcResult<Bytes> {
        debug!(
            "StubExecutionApi::call(from={:?}, to={:?}, gas={:?}, data_len={:?})",
            from,
            to,
            gas,
            data.as_ref().map(|d| d.len())
        );
        // Return empty bytes for now
        // In production, this would execute the call via revm
        Ok(Bytes::new())
    }

    async fn estimate_gas(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        _gas_price: Option<U256>,
        _value: Option<U256>,
        data: Option<Bytes>,
        _block: BlockNumberOrTag,
    ) -> RpcResult<u64> {
        debug!(
            "StubExecutionApi::estimate_gas(from={:?}, to={:?}, gas={:?}, data_len={:?})",
            from,
            to,
            gas,
            data.as_ref().map(|d| d.len())
        );
        // Return a reasonable default gas estimate
        // 21000 for simple transfer, higher for contract calls
        let base_gas = 21_000u64;
        let data_gas = data.map(|d| d.len() as u64 * 16).unwrap_or(0);
        Ok(base_gas + data_gas)
    }
}

// ============================================================================
// Real EVM Execution Implementation
// ============================================================================

/// Real EVM execution adapter using revm.
///
/// This adapter executes `eth_call` and `eth_estimateGas` requests using
/// the revm EVM implementation against the current blockchain state.
pub struct EvmExecutionApi<P: Provider> {
    /// Provider for reading state.
    provider: Arc<P>,
    /// Chain ID for this network.
    chain_id: u64,
    /// Block gas limit.
    block_gas_limit: u64,
    /// Base fee per gas.
    base_fee_per_gas: u64,
    /// Latest block number (for execution context).
    latest_block: AtomicU64,
}

impl<P: Provider> EvmExecutionApi<P> {
    /// Default block gas limit (30 million).
    const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;
    /// Default base fee (1 gwei).
    const DEFAULT_BASE_FEE: u64 = 1_000_000_000;
    /// Default gas limit for calls.
    const DEFAULT_CALL_GAS: u64 = 30_000_000;

    /// Create a new EVM execution adapter.
    pub fn new(provider: Arc<P>, chain_id: u64) -> Self {
        Self {
            provider,
            chain_id,
            block_gas_limit: Self::DEFAULT_BLOCK_GAS_LIMIT,
            base_fee_per_gas: Self::DEFAULT_BASE_FEE,
            latest_block: AtomicU64::new(0),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(
        provider: Arc<P>,
        chain_id: u64,
        block_gas_limit: u64,
        base_fee_per_gas: u64,
    ) -> Self {
        Self {
            provider,
            chain_id,
            block_gas_limit,
            base_fee_per_gas,
            latest_block: AtomicU64::new(0),
        }
    }

    /// Update the latest block number.
    pub fn set_latest_block(&self, block: u64) {
        self.latest_block.store(block, Ordering::SeqCst);
    }

    /// Execute a call and return the result.
    fn execute_call_internal(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        gas_price: Option<U256>,
        value: Option<U256>,
        data: Option<Bytes>,
    ) -> RpcResult<(Bytes, u64)> {
        use cipherbft_execution::database::CipherBftDatabase;
        use revm::context::{BlockEnv, CfgEnv, Context, Evm, FrameStack, Journal, TxEnv};
        use revm::context_interface::result::{ExecutionResult, Output};
        use revm::handler::instructions::EthInstructions;
        use revm::handler::EthPrecompiles;
        use revm::primitives::hardfork::SpecId;
        use revm::primitives::TxKind;

        // Type alias to reduce complexity (satisfies clippy::type_complexity)
        type EvmContext<DB> = Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, ()>;

        // Create a database wrapper for state access
        let db = CipherBftDatabase::new(Arc::clone(&self.provider));

        // Build the EVM context
        let block_number = self.latest_block.load(Ordering::SeqCst);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create context with database
        let mut ctx: EvmContext<CipherBftDatabase<Arc<P>>> = Context::new(db, SpecId::CANCUN);

        // Configure block environment
        ctx.block.number = alloy_primitives::U256::from(block_number);
        ctx.block.timestamp = alloy_primitives::U256::from(timestamp);
        ctx.block.gas_limit = self.block_gas_limit;
        ctx.block.basefee = self.base_fee_per_gas;

        // Configure chain settings
        ctx.cfg.chain_id = self.chain_id;

        // Set up transaction environment
        ctx.tx.caller = from.unwrap_or(Address::ZERO);
        ctx.tx.gas_limit = gas.unwrap_or(Self::DEFAULT_CALL_GAS);
        ctx.tx.gas_price = gas_price
            .map(|p| p.try_into().unwrap_or(self.base_fee_per_gas as u128))
            .unwrap_or(self.base_fee_per_gas as u128);
        ctx.tx.kind = match to {
            Some(addr) => TxKind::Call(addr),
            None => TxKind::Create,
        };
        ctx.tx.value = value.unwrap_or(U256::ZERO);
        ctx.tx.data = data.unwrap_or_default();
        ctx.tx.nonce = 0; // For calls, nonce doesn't matter

        // Build the EVM with standard precompiles
        let mut evm = Evm {
            ctx,
            inspector: (),
            instruction: EthInstructions::default(),
            precompiles: EthPrecompiles::default(),
            frame_stack: FrameStack::new_prealloc(8),
        };

        // Clone tx_env before passing to transact
        let tx_env = evm.ctx.tx.clone();

        // Execute the transaction
        use revm::handler::ExecuteEvm;
        let result = evm.transact(tx_env).map_err(|e| {
            debug!("EVM execution error: {:?}", e);
            RpcError::Execution(format!("EVM execution failed: {e:?}"))
        })?;

        // Process the result (result is ExecResultAndState, access .result for ExecutionResult)
        let gas_used = result.result.gas_used();
        let output = match result.result {
            ExecutionResult::Success { output, .. } => match output {
                Output::Call(data) => data,
                Output::Create(_, addr) => {
                    // For contract creation, encode the address as bytes
                    addr.map(|a: Address| Bytes::copy_from_slice(a.as_slice()))
                        .unwrap_or_default()
                }
            },
            ExecutionResult::Revert { output, .. } => {
                return Err(RpcError::Execution(format!(
                    "Execution reverted: 0x{}",
                    hex::encode(&output)
                )));
            }
            ExecutionResult::Halt { reason, .. } => {
                return Err(RpcError::Execution(format!("Execution halted: {reason:?}")));
            }
        };

        Ok((output, gas_used))
    }
}

#[async_trait]
impl<P: Provider + 'static> ExecutionApi for EvmExecutionApi<P> {
    async fn call(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        gas_price: Option<U256>,
        value: Option<U256>,
        data: Option<Bytes>,
        _block: BlockNumberOrTag,
    ) -> RpcResult<Bytes> {
        debug!(
            "EvmExecutionApi::call(from={:?}, to={:?}, gas={:?}, data_len={:?})",
            from,
            to,
            gas,
            data.as_ref().map(|d| d.len())
        );

        let (output, gas_used) =
            self.execute_call_internal(from, to, gas, gas_price, value, data)?;

        trace!(
            "eth_call result: {} bytes, {} gas used",
            output.len(),
            gas_used
        );
        Ok(output)
    }

    async fn estimate_gas(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        gas_price: Option<U256>,
        value: Option<U256>,
        data: Option<Bytes>,
        _block: BlockNumberOrTag,
    ) -> RpcResult<u64> {
        debug!(
            "EvmExecutionApi::estimate_gas(from={:?}, to={:?}, gas={:?}, data_len={:?})",
            from,
            to,
            gas,
            data.as_ref().map(|d| d.len())
        );

        let (_, gas_used) = self.execute_call_internal(from, to, gas, gas_price, value, data)?;

        // Add a small buffer to the gas estimate (10%)
        let estimated = gas_used + (gas_used / 10);
        trace!(
            "eth_estimateGas result: {} (actual: {})",
            estimated,
            gas_used
        );
        Ok(estimated)
    }
}

/// Stub network adapter.
///
/// This adapter provides placeholder implementations for network operations.
/// Replace with actual network layer integration when ready.
pub struct StubNetworkApi {
    /// Whether the node is listening (configurable for testing).
    listening: bool,
    /// Simulated peer count (configurable for testing).
    peer_count: u64,
}

impl StubNetworkApi {
    /// Create a new stub network adapter.
    pub fn new() -> Self {
        Self {
            listening: true,
            peer_count: 0,
        }
    }

    /// Create a stub network adapter with custom settings.
    pub fn with_peers(peer_count: u64) -> Self {
        Self {
            listening: true,
            peer_count,
        }
    }

    /// Set the peer count (for testing).
    pub fn set_peer_count(&mut self, count: u64) {
        self.peer_count = count;
    }

    /// Set listening status (for testing).
    pub fn set_listening(&mut self, listening: bool) {
        self.listening = listening;
    }
}

impl Default for StubNetworkApi {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkApi for StubNetworkApi {
    async fn peer_count(&self) -> RpcResult<u64> {
        trace!("StubNetworkApi::peer_count");
        Ok(self.peer_count)
    }

    async fn is_listening(&self) -> RpcResult<bool> {
        trace!("StubNetworkApi::is_listening");
        Ok(self.listening)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_execution::database::InMemoryProvider;

    #[tokio::test]
    async fn test_provider_based_storage_empty() {
        let provider = Arc::new(InMemoryProvider::new());
        let storage = ProviderBasedRpcStorage::new(provider, 85300);

        // Should return zero for non-existent accounts
        let balance = storage
            .get_balance(Address::ZERO, BlockNumberOrTag::Latest)
            .await
            .unwrap();
        assert_eq!(balance, U256::ZERO);

        let nonce = storage
            .get_transaction_count(Address::ZERO, BlockNumberOrTag::Latest)
            .await
            .unwrap();
        assert_eq!(nonce, 0);

        let code = storage
            .get_code(Address::ZERO, BlockNumberOrTag::Latest)
            .await
            .unwrap();
        assert!(code.is_empty());
    }

    #[tokio::test]
    async fn test_provider_based_storage_with_account() {
        use cipherbft_execution::database::Account;

        let provider = Arc::new(InMemoryProvider::new());

        // Create an account with balance
        let addr = Address::repeat_byte(0x42);
        let account = Account {
            nonce: 5,
            balance: U256::from(1000000000000000000u128), // 1 ETH
            code_hash: B256::ZERO,
            storage_root: B256::ZERO,
        };
        provider.set_account(addr, account).unwrap();

        let storage = ProviderBasedRpcStorage::new(provider, 85300);

        // Should return the account balance
        let balance = storage
            .get_balance(addr, BlockNumberOrTag::Latest)
            .await
            .unwrap();
        assert_eq!(balance, U256::from(1000000000000000000u128));

        // Should return the account nonce
        let nonce = storage
            .get_transaction_count(addr, BlockNumberOrTag::Latest)
            .await
            .unwrap();
        assert_eq!(nonce, 5);
    }

    #[tokio::test]
    async fn test_provider_based_storage_with_storage() {
        let provider = Arc::new(InMemoryProvider::new());

        let addr = Address::repeat_byte(0x42);
        let slot = U256::from(1);
        let value = U256::from(42);

        provider.set_storage(addr, slot, value).unwrap();

        let storage = ProviderBasedRpcStorage::new(provider, 85300);

        let result = storage
            .get_storage_at(addr, slot, BlockNumberOrTag::Latest)
            .await
            .unwrap();
        assert_eq!(result, B256::from(value.to_be_bytes::<32>()));
    }

    #[tokio::test]
    async fn test_provider_based_storage_latest_block() {
        let provider = Arc::new(InMemoryProvider::new());
        let storage = ProviderBasedRpcStorage::new(provider, 85300);

        assert_eq!(storage.latest_block_number().await.unwrap(), 0);

        storage.set_latest_block(100);
        assert_eq!(storage.latest_block_number().await.unwrap(), 100);
    }

    #[tokio::test]
    async fn test_provider_based_storage_sync_status() {
        let provider = Arc::new(InMemoryProvider::new());
        let storage = ProviderBasedRpcStorage::new(provider, 85300);

        // Initially not syncing
        let status = storage.sync_status().await.unwrap();
        assert!(matches!(status, SyncStatus::NotSyncing));

        // Set syncing
        storage.set_syncing(0, 50, 100);
        let status = storage.sync_status().await.unwrap();
        match status {
            SyncStatus::Syncing {
                starting_block,
                current_block,
                highest_block,
            } => {
                assert_eq!(starting_block, 0);
                assert_eq!(current_block, 50);
                assert_eq!(highest_block, 100);
            }
            _ => panic!("Expected Syncing status"),
        }

        // Mark as synced
        storage.set_synced();
        let status = storage.sync_status().await.unwrap();
        assert!(matches!(status, SyncStatus::NotSyncing));
    }

    #[tokio::test]
    async fn test_stub_storage() {
        let storage = StubRpcStorage::default();

        assert_eq!(storage.latest_block_number().await.unwrap(), 0);
        assert!(matches!(
            storage.sync_status().await.unwrap(),
            SyncStatus::NotSyncing
        ));
        assert_eq!(
            storage
                .get_balance(Address::ZERO, BlockNumberOrTag::Latest)
                .await
                .unwrap(),
            U256::ZERO
        );
    }

    #[tokio::test]
    async fn test_stub_mempool() {
        let mempool = StubMempoolApi::new();

        // Submit should return a valid hash
        let tx_bytes = Bytes::from(vec![0x01, 0x02, 0x03]);
        let hash = mempool.submit_transaction(tx_bytes).await.unwrap();
        assert!(!hash.is_zero());

        // Pending transactions should be empty
        let pending = mempool.get_pending_transactions().await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_stub_execution() {
        let executor = StubExecutionApi::new();

        // Call should return empty bytes
        let result = executor
            .call(None, None, None, None, None, None, BlockNumberOrTag::Latest)
            .await
            .unwrap();
        assert!(result.is_empty());

        // Estimate gas should return reasonable value
        let gas = executor
            .estimate_gas(None, None, None, None, None, None, BlockNumberOrTag::Latest)
            .await
            .unwrap();
        assert_eq!(gas, 21_000);
    }

    #[tokio::test]
    async fn test_stub_network() {
        let mut network = StubNetworkApi::new();

        assert!(network.is_listening().await.unwrap());
        assert_eq!(network.peer_count().await.unwrap(), 0);

        network.set_peer_count(5);
        assert_eq!(network.peer_count().await.unwrap(), 5);

        network.set_listening(false);
        assert!(!network.is_listening().await.unwrap());
    }
}
