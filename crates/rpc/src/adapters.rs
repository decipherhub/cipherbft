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
use alloy_rpc_types_eth::{Filter, Log, Transaction, TransactionReceipt};
use async_trait::async_trait;
use cipherbft_execution::database::Provider;
use cipherbft_mempool::pool::RecoveredTx;
use cipherbft_mempool::CipherBftPool;
use cipherbft_storage::mdbx::{
    MdbxBlockStore, MdbxLogStore, MdbxReceiptStore, MdbxTransactionStore,
};
use cipherbft_storage::{
    BlockStore, LogFilter as StorageLogFilter, LogStore, ReceiptStore, StoredLog, TransactionStore,
};
use parking_lot::RwLock;
use reth_primitives::TransactionSigned;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, trace, warn};

use cipherbft_execution::AccountProof;

use crate::error::{RpcError, RpcResult};
use crate::traits::{
    BlockNumberOrTag, ExecutionApi, MempoolApi, NetworkApi, RpcProofStorage, RpcStorage, SyncStatus,
};
use crate::types::{RpcBlock, RpcTransaction};

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
    ) -> RpcResult<Option<RpcBlock>> {
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
    ) -> RpcResult<Option<RpcBlock>> {
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

    async fn get_block_receipts(
        &self,
        block: BlockNumberOrTag,
    ) -> RpcResult<Option<Vec<TransactionReceipt>>> {
        trace!("ProviderBasedRpcStorage::get_block_receipts({:?})", block);
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

#[async_trait]
impl<P: Provider + 'static> RpcProofStorage for ProviderBasedRpcStorage<P> {
    async fn get_proof(
        &self,
        address: Address,
        storage_keys: Vec<U256>,
        _block: BlockNumberOrTag,
    ) -> RpcResult<AccountProof> {
        debug!(
            "ProviderBasedRpcStorage::get_proof({}, {} keys)",
            address,
            storage_keys.len()
        );

        // Get all accounts from provider
        let accounts = self
            .provider
            .get_all_accounts()
            .map_err(|e| RpcError::Storage(format!("Failed to get accounts: {}", e)))?;

        // Storage getter function
        let provider = Arc::clone(&self.provider);
        let storage_getter = move |addr: Address| -> cipherbft_execution::Result<
            std::collections::BTreeMap<U256, U256>,
        > {
            provider.get_all_storage(addr).map_err(|e| {
                cipherbft_execution::ExecutionError::Internal(format!(
                    "Failed to get storage: {}",
                    e
                ))
            })
        };

        // Generate the proof
        cipherbft_execution::generate_account_proof(
            &accounts,
            storage_getter,
            address,
            storage_keys,
        )
        .map_err(|e| RpcError::Storage(format!("Failed to generate proof: {}", e)))
    }
}

// ============================================================================
// MDBX-backed RPC Storage Implementation
// ============================================================================

/// MDBX-backed RPC storage that uses real block, receipt, and transaction stores.
///
/// This adapter combines the execution layer's `Provider` trait for state queries
/// with MDBX-backed block, receipt, and transaction stores for historical data.
/// It bridges the gap between the RPC interface and the persistent storage layer.
///
/// # Architecture
///
/// - State queries (balance, code, storage, nonce): Delegated to the `Provider`
/// - Block queries: Use `MdbxBlockStore`
/// - Receipt queries: Use `MdbxReceiptStore`
/// - Transaction queries: Use `MdbxTransactionStore` (for full transaction bodies)
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
    /// Transaction storage for full transaction bodies.
    transaction_store: Option<Arc<MdbxTransactionStore>>,
    /// Log storage for eth_getLogs queries.
    log_store: Option<Arc<MdbxLogStore>>,
    /// Chain ID.
    chain_id: u64,
    /// Latest block number (updated by consensus).
    latest_block: AtomicU64,
    /// Sync status tracking.
    sync_state: RwLock<SyncStateTracker>,
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
            transaction_store: None,
            log_store: None,
            chain_id,
            latest_block: AtomicU64::new(0),
            sync_state: RwLock::new(SyncStateTracker::default()),
        }
    }

    /// Create new MDBX-backed RPC storage with log store.
    ///
    /// # Arguments
    ///
    /// * `provider` - Provider for state queries
    /// * `block_store` - MDBX-backed block store
    /// * `receipt_store` - MDBX-backed receipt store
    /// * `log_store` - MDBX-backed log store for eth_getLogs
    /// * `chain_id` - Chain ID for this network
    pub fn with_log_store(
        provider: Arc<P>,
        block_store: Arc<MdbxBlockStore>,
        receipt_store: Arc<MdbxReceiptStore>,
        log_store: Arc<MdbxLogStore>,
        chain_id: u64,
    ) -> Self {
        Self {
            provider,
            block_store,
            receipt_store,
            transaction_store: None,
            log_store: Some(log_store),
            chain_id,
            latest_block: AtomicU64::new(0),
            sync_state: RwLock::new(SyncStateTracker::default()),
        }
    }

    /// Create new MDBX-backed RPC storage with transaction and log stores.
    ///
    /// This constructor enables full transaction body support for
    /// `eth_getBlockByNumber` and `eth_getBlockByHash` with `full_transactions=true`.
    ///
    /// # Arguments
    ///
    /// * `provider` - Provider for state queries
    /// * `block_store` - MDBX-backed block store
    /// * `receipt_store` - MDBX-backed receipt store
    /// * `transaction_store` - MDBX-backed transaction store for full tx bodies
    /// * `log_store` - MDBX-backed log store for eth_getLogs
    /// * `chain_id` - Chain ID for this network
    pub fn with_transaction_store(
        provider: Arc<P>,
        block_store: Arc<MdbxBlockStore>,
        receipt_store: Arc<MdbxReceiptStore>,
        transaction_store: Arc<MdbxTransactionStore>,
        log_store: Option<Arc<MdbxLogStore>>,
        chain_id: u64,
    ) -> Self {
        Self {
            provider,
            block_store,
            receipt_store,
            transaction_store: Some(transaction_store),
            log_store,
            chain_id,
            latest_block: AtomicU64::new(0),
            sync_state: RwLock::new(SyncStateTracker::default()),
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

    /// Get reference to log store (if configured).
    pub fn log_store(&self) -> Option<&Arc<MdbxLogStore>> {
        self.log_store.as_ref()
    }

    /// Get reference to transaction store (if configured).
    pub fn transaction_store(&self) -> Option<&Arc<MdbxTransactionStore>> {
        self.transaction_store.as_ref()
    }

    /// Get reference to provider.
    pub fn provider(&self) -> &Arc<P> {
        &self.provider
    }

    /// Get chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Update sync status (called by sync service).
    ///
    /// This should be called by the sync service to indicate progress.
    ///
    /// # Arguments
    ///
    /// * `starting` - Block number when sync started
    /// * `current` - Current block during sync
    /// * `highest` - Highest known block
    pub fn set_syncing(&self, starting: u64, current: u64, highest: u64) {
        let mut state = self.sync_state.write();
        state.is_syncing = true;
        state.starting_block = starting;
        state.current_block = current;
        state.highest_block = highest;
    }

    /// Mark sync as complete.
    ///
    /// This should be called when the node has finished syncing.
    pub fn set_synced(&self) {
        let mut state = self.sync_state.write();
        state.is_syncing = false;
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
            .map(|(idx, storage_log)| Log {
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

    /// Convert RPC Filter to storage LogFilter.
    fn rpc_filter_to_storage_filter(filter: &Filter) -> StorageLogFilter {
        // Extract block range
        let (from_block, to_block) = filter.extract_block_range();
        let block_hash = filter.get_block_hash().map(|h| h.0);

        // Convert addresses: FilterSet<Address> -> Vec<[u8; 20]>
        let addresses: Vec<[u8; 20]> = filter.address.iter().map(|addr| addr.0 .0).collect();

        // Convert topics: [Topic; 4] -> Vec<Option<Vec<[u8; 32]>>>
        // Topic is FilterSet<B256>, and each position can match any of the topics in the set
        let topics: Vec<Option<Vec<[u8; 32]>>> = filter
            .topics
            .iter()
            .map(|topic_set| {
                if topic_set.is_empty() {
                    None // Match any topic at this position
                } else {
                    Some(topic_set.iter().map(|t| t.0).collect())
                }
            })
            .collect();

        StorageLogFilter {
            from_block,
            to_block,
            block_hash,
            addresses,
            topics,
        }
    }

    /// Convert storage StoredLog to RPC Log.
    fn stored_log_to_rpc_log(stored: StoredLog) -> Log {
        use alloy_primitives::LogData;

        // Convert topics from [u8; 32] to B256
        let topics: Vec<B256> = stored.topics.iter().map(|t| B256::from(*t)).collect();

        // Create the inner log data
        let log_data = LogData::new_unchecked(topics, Bytes::from(stored.data));

        // Create the primitive log
        let inner = alloy_primitives::Log {
            address: Address::from(stored.address),
            data: log_data,
        };

        // Build the full RPC log with metadata
        Log {
            inner,
            block_hash: Some(B256::from(stored.block_hash)),
            block_number: Some(stored.block_number),
            block_timestamp: None, // Not stored in current StoredLog
            transaction_hash: Some(B256::from(stored.transaction_hash)),
            transaction_index: Some(stored.transaction_index as u64),
            log_index: Some(stored.log_index as u64),
            removed: stored.removed,
        }
    }

    /// Convert a storage transaction to an RPC transaction.
    ///
    /// This converts the raw storage format (designed for MDBX efficiency) back to
    /// the Ethereum JSON-RPC `Transaction` format with all required fields.
    fn storage_transaction_to_rpc(
        &self,
        storage_tx: cipherbft_storage::transactions::Transaction,
    ) -> Transaction {
        use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxEnvelope, TxLegacy};
        use alloy_primitives::Signature;
        use reth_primitives_traits::Recovered;

        let hash = B256::from(storage_tx.hash);
        let from = Address::from(storage_tx.from);
        let to = storage_tx.to.map(Address::from);
        let value = U256::from_be_bytes(storage_tx.value);
        let input = Bytes::from(storage_tx.input);

        // Reconstruct signature from stored components
        // For typed transactions (EIP-2930, EIP-1559): v is parity (0 or 1)
        // For legacy: v includes chain_id encoding, extract parity
        let parity = if storage_tx.transaction_type == 0 {
            // Legacy: v = 27 + parity or v = chain_id * 2 + 35 + parity
            if storage_tx.v >= 35 {
                // EIP-155: parity = (v - 35) % 2
                !(storage_tx.v - 35).is_multiple_of(2)
            } else {
                // Pre-EIP-155: parity = v - 27
                (storage_tx.v - 27) != 0
            }
        } else {
            // Typed transactions: v is already parity
            storage_tx.v != 0
        };

        let r = U256::from_be_bytes(storage_tx.r);
        let s = U256::from_be_bytes(storage_tx.s);
        let signature = Signature::new(r, s, parity);

        // Build the transaction envelope based on type
        let tx_envelope: TxEnvelope = match storage_tx.transaction_type {
            0 => {
                // Legacy transaction
                let legacy = TxLegacy {
                    chain_id: storage_tx.chain_id,
                    nonce: storage_tx.nonce,
                    gas_price: storage_tx.gas_price.unwrap_or(0) as u128,
                    gas_limit: storage_tx.gas,
                    to: to.into(),
                    value,
                    input,
                };
                TxEnvelope::Legacy(Signed::new_unchecked(legacy, signature, hash))
            }
            1 => {
                // EIP-2930 transaction
                let eip2930 = TxEip2930 {
                    chain_id: storage_tx.chain_id.unwrap_or(1),
                    nonce: storage_tx.nonce,
                    gas_price: storage_tx.gas_price.unwrap_or(0) as u128,
                    gas_limit: storage_tx.gas,
                    to: to.into(),
                    value,
                    input,
                    access_list: Default::default(), // Access list not stored
                };
                TxEnvelope::Eip2930(Signed::new_unchecked(eip2930, signature, hash))
            }
            2 => {
                // EIP-1559 transaction
                let eip1559 = TxEip1559 {
                    chain_id: storage_tx.chain_id.unwrap_or(1),
                    nonce: storage_tx.nonce,
                    max_fee_per_gas: storage_tx.max_fee_per_gas.unwrap_or(0) as u128,
                    max_priority_fee_per_gas: storage_tx.max_priority_fee_per_gas.unwrap_or(0)
                        as u128,
                    gas_limit: storage_tx.gas,
                    to: to.into(),
                    value,
                    input,
                    access_list: Default::default(), // Access list not stored
                };
                TxEnvelope::Eip1559(Signed::new_unchecked(eip1559, signature, hash))
            }
            _ => {
                // Default to legacy for unknown types
                let legacy = TxLegacy {
                    chain_id: storage_tx.chain_id,
                    nonce: storage_tx.nonce,
                    gas_price: storage_tx.gas_price.unwrap_or(0) as u128,
                    gas_limit: storage_tx.gas,
                    to: to.into(),
                    value,
                    input,
                };
                TxEnvelope::Legacy(Signed::new_unchecked(legacy, signature, hash))
            }
        };

        // Wrap in Recovered to include sender
        let recovered = Recovered::new_unchecked(tx_envelope, from);

        // Build the RPC transaction with block context
        Transaction {
            inner: recovered,
            block_hash: Some(B256::from(storage_tx.block_hash)),
            block_number: Some(storage_tx.block_number),
            transaction_index: Some(storage_tx.transaction_index as u64),
            effective_gas_price: storage_tx.gas_price.map(|p| p as u128),
        }
    }
}

#[async_trait]
impl<P: Provider + 'static> RpcStorage for MdbxRpcStorage<P> {
    async fn get_block_by_number(
        &self,
        number: BlockNumberOrTag,
        full_transactions: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let resolved = self.resolve_block_number(number);
        trace!(
            "MdbxRpcStorage::get_block_by_number({:?} -> {}, full={})",
            number,
            resolved,
            full_transactions
        );

        // Query the block store
        match self.block_store.get_block_by_number(resolved).await {
            Ok(Some(storage_block)) => {
                debug!(
                    "Found block {} with hash {:?}",
                    resolved, storage_block.hash
                );

                // Handle full_transactions parameter
                if full_transactions {
                    // Fetch full transaction bodies if transaction store is available
                    if let Some(tx_store) = &self.transaction_store {
                        match tx_store.get_transactions_by_block(resolved).await {
                            Ok(txs) => {
                                let rpc_txs: Vec<RpcTransaction> =
                                    txs.into_iter().map(RpcTransaction::from_storage).collect();
                                debug!(
                                    "Returning block {} with {} full transactions",
                                    resolved,
                                    rpc_txs.len()
                                );
                                Ok(Some(RpcBlock::from_storage_full(storage_block, rpc_txs)))
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to fetch transactions for block {}: {}, falling back to hashes",
                                    resolved, e
                                );
                                // Fall back to returning hashes only
                                Ok(Some(RpcBlock::from_storage(storage_block)))
                            }
                        }
                    } else {
                        // No transaction store configured, return hashes only
                        debug!(
                            "Transaction store not configured, returning block {} with hashes only",
                            resolved
                        );
                        Ok(Some(RpcBlock::from_storage(storage_block)))
                    }
                } else {
                    // Return hashes only
                    Ok(Some(RpcBlock::from_storage(storage_block)))
                }
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
    ) -> RpcResult<Option<RpcBlock>> {
        trace!(
            "MdbxRpcStorage::get_block_by_hash({}, full={})",
            hash,
            full_transactions
        );

        let hash_bytes: [u8; 32] = hash.into();

        // Query the block store
        match self.block_store.get_block_by_hash(&hash_bytes).await {
            Ok(Some(storage_block)) => {
                let block_number = storage_block.number;
                debug!("Found block {} with hash {}", block_number, hash);

                // Handle full_transactions parameter
                if full_transactions {
                    // Fetch full transaction bodies if transaction store is available
                    if let Some(tx_store) = &self.transaction_store {
                        match tx_store.get_transactions_by_block(block_number).await {
                            Ok(txs) => {
                                let rpc_txs: Vec<RpcTransaction> =
                                    txs.into_iter().map(RpcTransaction::from_storage).collect();
                                debug!(
                                    "Returning block {} with {} full transactions",
                                    block_number,
                                    rpc_txs.len()
                                );
                                Ok(Some(RpcBlock::from_storage_full(storage_block, rpc_txs)))
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to fetch transactions for block {}: {}, falling back to hashes",
                                    block_number, e
                                );
                                // Fall back to returning hashes only
                                Ok(Some(RpcBlock::from_storage(storage_block)))
                            }
                        }
                    } else {
                        // No transaction store configured, return hashes only
                        debug!(
                            "Transaction store not configured, returning block {} with hashes only",
                            block_number
                        );
                        Ok(Some(RpcBlock::from_storage(storage_block)))
                    }
                } else {
                    // Return hashes only
                    Ok(Some(RpcBlock::from_storage(storage_block)))
                }
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

        // Check if transaction store is configured
        let tx_store = match &self.transaction_store {
            Some(store) => store,
            None => {
                trace!("Transaction store not configured, returning None");
                return Ok(None);
            }
        };

        let hash_bytes: [u8; 32] = hash.into();

        // Query the transaction store
        match tx_store.get_transaction(&hash_bytes).await {
            Ok(Some(storage_tx)) => {
                debug!(
                    "Found transaction {} in block {}",
                    hash, storage_tx.block_number
                );
                let rpc_tx = self.storage_transaction_to_rpc(storage_tx);
                Ok(Some(rpc_tx))
            }
            Ok(None) => {
                trace!("Transaction {} not found", hash);
                Ok(None)
            }
            Err(e) => {
                warn!("Failed to query transaction {}: {}", hash, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
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

    async fn get_block_receipts(
        &self,
        block: BlockNumberOrTag,
    ) -> RpcResult<Option<Vec<TransactionReceipt>>> {
        let block_number = self.resolve_block_number(block);
        trace!(
            "MdbxRpcStorage::get_block_receipts({:?} -> {})",
            block,
            block_number
        );

        // First check if the block exists
        match self.block_store.get_block_by_number(block_number).await {
            Ok(Some(_)) => {
                // Block exists, get all receipts
                match self.receipt_store.get_receipts_by_block(block_number).await {
                    Ok(storage_receipts) => {
                        debug!(
                            "Found {} receipts for block {}",
                            storage_receipts.len(),
                            block_number
                        );
                        let rpc_receipts: Vec<TransactionReceipt> = storage_receipts
                            .into_iter()
                            .map(|r| self.storage_receipt_to_rpc(r))
                            .collect();
                        Ok(Some(rpc_receipts))
                    }
                    Err(e) => {
                        warn!("Error getting receipts for block {}: {}", block_number, e);
                        Err(RpcError::Storage(e.to_string()))
                    }
                }
            }
            Ok(None) => {
                trace!("Block {} not found", block_number);
                Ok(None)
            }
            Err(e) => {
                warn!("Error checking block {}: {}", block_number, e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn get_logs(&self, filter: Filter) -> RpcResult<Vec<Log>> {
        trace!("MdbxRpcStorage::get_logs({:?})", filter);

        // If no log store is configured, return empty
        let log_store = match &self.log_store {
            Some(store) => store,
            None => {
                debug!("MdbxRpcStorage::get_logs - no log store configured, returning empty");
                return Ok(Vec::new());
            }
        };

        // Convert RPC filter to storage filter
        let storage_filter = Self::rpc_filter_to_storage_filter(&filter);

        // Maximum results to prevent DoS (configurable in RpcConfig)
        const MAX_LOG_RESULTS: usize = 10_000;

        // Query logs from storage
        match log_store.get_logs(&storage_filter, MAX_LOG_RESULTS).await {
            Ok(stored_logs) => {
                debug!("MdbxRpcStorage::get_logs found {} logs", stored_logs.len());
                // Convert stored logs to RPC logs
                let rpc_logs: Vec<Log> = stored_logs
                    .into_iter()
                    .map(Self::stored_log_to_rpc_log)
                    .collect();
                Ok(rpc_logs)
            }
            Err(e) => {
                warn!("MdbxRpcStorage::get_logs error: {}", e);
                Err(RpcError::Storage(e.to_string()))
            }
        }
    }

    async fn latest_block_number(&self) -> RpcResult<u64> {
        trace!("MdbxRpcStorage::latest_block_number");
        Ok(self.latest_block.load(Ordering::SeqCst))
    }

    async fn sync_status(&self) -> RpcResult<SyncStatus> {
        trace!("MdbxRpcStorage::sync_status");
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
        trace!("MdbxRpcStorage::get_balance({}, {:?})", address, block);

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
        trace!("MdbxRpcStorage::get_code({}, {:?})", address, block);

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
    ) -> RpcResult<Option<RpcBlock>> {
        trace!("StubRpcStorage::get_block_by_number({:?})", number);
        Ok(None)
    }

    async fn get_block_by_hash(
        &self,
        hash: B256,
        _full_transactions: bool,
    ) -> RpcResult<Option<RpcBlock>> {
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

    async fn get_block_receipts(
        &self,
        block: BlockNumberOrTag,
    ) -> RpcResult<Option<Vec<TransactionReceipt>>> {
        trace!("StubRpcStorage::get_block_receipts({:?})", block);
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

#[async_trait]
impl RpcProofStorage for StubRpcStorage {
    async fn get_proof(
        &self,
        address: Address,
        storage_keys: Vec<U256>,
        _block: BlockNumberOrTag,
    ) -> RpcResult<AccountProof> {
        debug!(
            "StubRpcStorage::get_proof({}, {} keys)",
            address,
            storage_keys.len()
        );

        // Return a minimal stub proof
        use cipherbft_execution::StorageProof;
        const EMPTY_ROOT_HASH: B256 = B256::new([
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
            0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
            0xe3, 0x63, 0xb4, 0x21,
        ]);

        let storage_proofs: Vec<StorageProof> = storage_keys
            .into_iter()
            .map(|key| StorageProof {
                key,
                value: U256::ZERO,
                proof: vec![],
            })
            .collect();

        Ok(AccountProof {
            address,
            balance: U256::ZERO,
            code_hash: cipherbft_execution::KECCAK_EMPTY,
            nonce: 0,
            storage_hash: EMPTY_ROOT_HASH,
            account_proof: vec![],
            storage_proof: storage_proofs,
        })
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
                gas_price: signed_tx.max_fee_per_gas(),
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
                gas_price: signed_tx.max_fee_per_gas(),
                gas_limit: signed_tx.gas_limit(),
                to: signed_tx.to().into(),
                value: signed_tx.value(),
                input: signed_tx.input().clone(),
                access_list: signed_tx.access_list().cloned().unwrap_or_default(),
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
                max_fee_per_gas: signed_tx.max_fee_per_gas(),
                max_priority_fee_per_gas: signed_tx.max_priority_fee_per_gas().unwrap_or(0),
                gas_limit: signed_tx.gas_limit(),
                to: signed_tx.to().into(),
                value: signed_tx.value(),
                input: signed_tx.input().clone(),
                access_list: signed_tx.access_list().cloned().unwrap_or_default(),
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
                gas_price: signed_tx.max_fee_per_gas(),
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

/// Convert a storage block to an RPC block format.
///
/// This is a standalone function for use by the node when broadcasting
/// new blocks to WebSocket subscribers via `eth_subscribe("newHeads")`.
///
/// Returns an `RpcBlock` which serializes all numeric fields as hex strings
/// following the Ethereum JSON-RPC specification. This ensures compatibility
/// with block explorers like Blockscout that require strict hex encoding.
pub fn storage_block_to_rpc_block(
    storage_block: cipherbft_storage::blocks::Block,
    _full_txs: bool,
) -> crate::types::RpcBlock {
    // Use the RpcBlock's from_storage constructor for proper hex serialization
    crate::types::RpcBlock::from_storage(storage_block)
}

// ============================================================================
// Stub Debug Execution Implementation
// ============================================================================

/// Stub debug execution adapter.
///
/// This adapter provides placeholder implementations for debug tracing operations.
/// Replace with actual revm tracing integration when ready.
pub struct StubDebugExecutionApi {
    /// Latest block number (for consistency with EvmDebugExecutionApi).
    latest_block: AtomicU64,
}

impl StubDebugExecutionApi {
    /// Create a new stub debug execution adapter.
    pub fn new() -> Self {
        Self {
            latest_block: AtomicU64::new(0),
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
}

impl Default for StubDebugExecutionApi {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl crate::traits::DebugExecutionApi for StubDebugExecutionApi {
    async fn trace_transaction(
        &self,
        tx_hash: B256,
        _block: BlockNumberOrTag,
        _options: Option<cipherbft_execution::TraceOptions>,
    ) -> RpcResult<cipherbft_execution::TraceResult> {
        debug!("StubDebugExecutionApi::trace_transaction(hash={})", tx_hash);
        // Return an empty trace result for now
        Ok(cipherbft_execution::TraceResult {
            call_trace: None,
            struct_logs: Some(vec![]),
            state_diff: None,
            failed: false,
            gas: 21000,
            return_value: Some(Bytes::new()),
        })
    }

    async fn trace_call(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        _gas_price: Option<U256>,
        _value: Option<U256>,
        data: Option<Bytes>,
        _block: BlockNumberOrTag,
        _options: Option<cipherbft_execution::TraceOptions>,
    ) -> RpcResult<cipherbft_execution::TraceResult> {
        debug!(
            "StubDebugExecutionApi::trace_call(from={:?}, to={:?}, gas={:?}, data_len={:?})",
            from,
            to,
            gas,
            data.as_ref().map(|d| d.len())
        );
        // Return an empty trace result for now
        Ok(cipherbft_execution::TraceResult {
            call_trace: None,
            struct_logs: Some(vec![]),
            state_diff: None,
            failed: false,
            gas: gas.unwrap_or(21000),
            return_value: Some(Bytes::new()),
        })
    }

    async fn trace_block(
        &self,
        block: BlockNumberOrTag,
        _options: Option<cipherbft_execution::TraceOptions>,
    ) -> RpcResult<Vec<cipherbft_execution::TraceResult>> {
        debug!("StubDebugExecutionApi::trace_block(block={:?})", block);
        // Return empty traces for now
        Ok(vec![])
    }
}

// ============================================================================
// Real EVM Debug Execution Implementation
// ============================================================================

/// Real EVM debug execution adapter using revm with inspector support.
///
/// This adapter executes debug/trace operations using the revm EVM
/// implementation with actual Inspector integration for tracing.
pub struct EvmDebugExecutionApi<P, B = (), R = ()>
where
    P: Provider,
{
    /// Provider for reading state.
    provider: Arc<P>,
    /// Optional block store for trace_transaction/trace_block.
    block_store: Option<Arc<B>>,
    /// Optional receipt store for trace_transaction/trace_block.
    receipt_store: Option<Arc<R>>,
    /// Chain ID for this network.
    chain_id: u64,
    /// Block gas limit.
    block_gas_limit: u64,
    /// Base fee per gas.
    base_fee_per_gas: u64,
    /// Latest block number (for execution context).
    latest_block: AtomicU64,
}

impl<P: Provider> EvmDebugExecutionApi<P, (), ()> {
    /// Default block gas limit (30 million).
    const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;
    /// Default base fee (1 gwei).
    const DEFAULT_BASE_FEE: u64 = 1_000_000_000;

    /// Create a new EVM debug execution adapter without storage (trace_call only).
    pub fn new(provider: Arc<P>, chain_id: u64) -> Self {
        Self {
            provider,
            block_store: None,
            receipt_store: None,
            chain_id,
            block_gas_limit: Self::DEFAULT_BLOCK_GAS_LIMIT,
            base_fee_per_gas: Self::DEFAULT_BASE_FEE,
            latest_block: AtomicU64::new(0),
        }
    }
}

impl<P, B, R> EvmDebugExecutionApi<P, B, R>
where
    P: Provider,
    B: cipherbft_storage::BlockStore + Send + Sync + 'static,
    R: cipherbft_storage::ReceiptStore + Send + Sync + 'static,
{
    /// Default block gas limit (30 million).
    const DEFAULT_BLOCK_GAS_LIMIT_WITH_STORAGE: u64 = 30_000_000;
    /// Default base fee (1 gwei).
    const DEFAULT_BASE_FEE_WITH_STORAGE: u64 = 1_000_000_000;
    /// Default gas limit for calls.
    const DEFAULT_CALL_GAS: u64 = 30_000_000;

    /// Create a new EVM debug execution adapter with full storage support.
    pub fn with_storage(
        provider: Arc<P>,
        block_store: Arc<B>,
        receipt_store: Arc<R>,
        chain_id: u64,
    ) -> Self {
        Self {
            provider,
            block_store: Some(block_store),
            receipt_store: Some(receipt_store),
            chain_id,
            block_gas_limit: Self::DEFAULT_BLOCK_GAS_LIMIT_WITH_STORAGE,
            base_fee_per_gas: Self::DEFAULT_BASE_FEE_WITH_STORAGE,
            latest_block: AtomicU64::new(0),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(
        provider: Arc<P>,
        block_store: Option<Arc<B>>,
        receipt_store: Option<Arc<R>>,
        chain_id: u64,
        block_gas_limit: u64,
        base_fee_per_gas: u64,
    ) -> Self {
        Self {
            provider,
            block_store,
            receipt_store,
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

    /// Execute a call with CallTracer and return the trace result.
    #[allow(clippy::too_many_arguments)]
    fn trace_call_with_call_tracer(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        gas_price: Option<U256>,
        value: Option<U256>,
        data: Option<Bytes>,
        config: cipherbft_execution::CallTracerConfig,
    ) -> RpcResult<cipherbft_execution::TraceResult> {
        use cipherbft_execution::database::CipherBftDatabase;
        use cipherbft_execution::CallTracer;
        use revm::context::{BlockEnv, CfgEnv, Context, Evm, FrameStack, Journal, TxEnv};
        use revm::context_interface::result::{ExecutionResult, Output};
        use revm::handler::instructions::EthInstructions;
        use revm::handler::EthPrecompiles;
        use revm::primitives::hardfork::SpecId;
        use revm::primitives::TxKind;

        // Type alias for EVM context with CallTracer
        type EvmContextWithTracer<DB> = Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, ()>;

        // Create database and tracer
        let db = CipherBftDatabase::new(Arc::clone(&self.provider));
        let tracer = CallTracer::with_config(config);

        // Build the EVM context
        let block_number = self.latest_block.load(Ordering::SeqCst);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create context with database
        let mut ctx: EvmContextWithTracer<CipherBftDatabase<Arc<P>>> =
            Context::new(db, SpecId::CANCUN);

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
        ctx.tx.nonce = 0;

        // Build the EVM with tracer as inspector
        let mut evm = Evm {
            ctx,
            inspector: tracer,
            instruction: EthInstructions::default(),
            precompiles: EthPrecompiles::default(),
            frame_stack: FrameStack::new_prealloc(8),
        };

        // Clone tx_env before passing to transact
        let tx_env = evm.ctx.tx.clone();

        // Execute the transaction with tracing
        use revm::handler::ExecuteEvm;
        let result = evm.transact(tx_env).map_err(|e| {
            debug!("EVM trace execution error: {:?}", e);
            RpcError::Execution(format!("EVM trace execution failed: {e:?}"))
        })?;

        // Extract trace from inspector
        let call_trace = evm.inspector.into_trace();

        // Build trace result
        let gas_used = result.result.gas_used();
        let (failed, return_value) = match result.result {
            ExecutionResult::Success { output, .. } => {
                let output_bytes = match output {
                    Output::Call(data) => data,
                    Output::Create(_, addr) => addr
                        .map(|a| Bytes::copy_from_slice(a.as_slice()))
                        .unwrap_or_default(),
                };
                (false, Some(output_bytes))
            }
            ExecutionResult::Revert { output, .. } => (true, Some(output)),
            ExecutionResult::Halt { .. } => (true, None),
        };

        Ok(cipherbft_execution::TraceResult {
            call_trace,
            struct_logs: None,
            state_diff: None,
            failed,
            gas: gas_used,
            return_value,
        })
    }

    /// Execute a call with OpcodeTracer and return the trace result.
    #[allow(clippy::too_many_arguments)]
    fn trace_call_with_opcode_tracer(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        gas_price: Option<U256>,
        value: Option<U256>,
        data: Option<Bytes>,
        config: cipherbft_execution::OpcodeTracerConfig,
    ) -> RpcResult<cipherbft_execution::TraceResult> {
        use cipherbft_execution::database::CipherBftDatabase;
        use cipherbft_execution::OpcodeTracer;
        use revm::context::{BlockEnv, CfgEnv, Context, Evm, FrameStack, Journal, TxEnv};
        use revm::context_interface::result::{ExecutionResult, Output};
        use revm::handler::instructions::EthInstructions;
        use revm::handler::EthPrecompiles;
        use revm::primitives::hardfork::SpecId;
        use revm::primitives::TxKind;

        // Type alias for EVM context
        type EvmContextWithTracer<DB> = Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, ()>;

        // Create database and tracer
        let db = CipherBftDatabase::new(Arc::clone(&self.provider));
        let tracer = OpcodeTracer::with_config(config);

        // Build the EVM context
        let block_number = self.latest_block.load(Ordering::SeqCst);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create context with database
        let mut ctx: EvmContextWithTracer<CipherBftDatabase<Arc<P>>> =
            Context::new(db, SpecId::CANCUN);

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
        ctx.tx.nonce = 0;

        // Build the EVM with tracer as inspector
        let mut evm = Evm {
            ctx,
            inspector: tracer,
            instruction: EthInstructions::default(),
            precompiles: EthPrecompiles::default(),
            frame_stack: FrameStack::new_prealloc(8),
        };

        // Clone tx_env before passing to transact
        let tx_env = evm.ctx.tx.clone();

        // Execute the transaction with tracing
        use revm::handler::ExecuteEvm;
        let result = evm.transact(tx_env).map_err(|e| {
            debug!("EVM trace execution error: {:?}", e);
            RpcError::Execution(format!("EVM trace execution failed: {e:?}"))
        })?;

        // Extract trace from inspector
        let struct_logs = evm.inspector.into_steps();

        // Build trace result
        let gas_used = result.result.gas_used();
        let (failed, return_value) = match result.result {
            ExecutionResult::Success { output, .. } => {
                let output_bytes = match output {
                    Output::Call(data) => data,
                    Output::Create(_, addr) => addr
                        .map(|a| Bytes::copy_from_slice(a.as_slice()))
                        .unwrap_or_default(),
                };
                (false, Some(output_bytes))
            }
            ExecutionResult::Revert { output, .. } => (true, Some(output)),
            ExecutionResult::Halt { .. } => (true, None),
        };

        Ok(cipherbft_execution::TraceResult {
            call_trace: None,
            struct_logs: Some(struct_logs),
            state_diff: None,
            failed,
            gas: gas_used,
            return_value,
        })
    }
}

#[async_trait]
impl<P, B, R> crate::traits::DebugExecutionApi for EvmDebugExecutionApi<P, B, R>
where
    P: Provider + 'static,
    B: cipherbft_storage::BlockStore + Send + Sync + 'static,
    R: cipherbft_storage::ReceiptStore + Send + Sync + 'static,
{
    async fn trace_transaction(
        &self,
        tx_hash: B256,
        _block: BlockNumberOrTag,
        options: Option<cipherbft_execution::TraceOptions>,
    ) -> RpcResult<cipherbft_execution::TraceResult> {
        debug!("EvmDebugExecutionApi::trace_transaction(hash={})", tx_hash);

        // Check if we have storage configured
        let (block_store, receipt_store) = match (&self.block_store, &self.receipt_store) {
            (Some(b), Some(r)) => (b, r),
            _ => {
                return Err(RpcError::MethodNotSupported(
                    "debug_traceTransaction requires storage configuration. \
                     Use EvmDebugExecutionApi::with_storage() or use debug_traceCall instead."
                        .to_string(),
                ));
            }
        };

        // 1. Get the receipt to find the transaction's block
        let tx_hash_bytes: [u8; 32] = tx_hash.0;
        let receipt = receipt_store
            .get_receipt(&tx_hash_bytes)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to get receipt: {}", e)))?
            .ok_or_else(|| RpcError::NotFound(format!("Transaction {} not found", tx_hash)))?;

        // 2. Get the block to find transaction position
        let block = block_store
            .get_block_by_number(receipt.block_number)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| {
                RpcError::Internal(format!("Block {} not found", receipt.block_number))
            })?;

        // 3. Find transaction index in block
        let tx_index = block
            .transaction_hashes
            .iter()
            .position(|h| h == &tx_hash_bytes)
            .ok_or_else(|| {
                RpcError::Internal(format!(
                    "Transaction {} not found in block {}",
                    tx_hash, receipt.block_number
                ))
            })?;

        // 4. Re-execute all transactions up to and including the target
        // For now, we execute just the target transaction with the trace
        // Full implementation would require replaying previous txs to get correct state
        debug!(
            "Tracing transaction {} at index {} in block {}",
            tx_hash, tx_index, receipt.block_number
        );

        // Execute the transaction with tracing
        // We use the receipt data to reconstruct the call parameters
        let from = Some(Address::from_slice(&receipt.from));
        let to = receipt.to.map(|t| Address::from_slice(&t));
        let gas = Some(receipt.gas_used);

        // Determine tracer type
        let tracer_type = options.as_ref().and_then(|o| o.tracer.as_deref());

        match tracer_type {
            Some("callTracer") => {
                let config = options
                    .as_ref()
                    .and_then(|o| o.tracer_config.as_ref())
                    .and_then(|v| {
                        serde_json::from_value::<cipherbft_execution::CallTracerConfig>(v.clone())
                            .ok()
                    })
                    .unwrap_or_default();

                self.trace_call_with_call_tracer(from, to, gas, None, None, None, config)
            }
            _ => {
                let config = options
                    .as_ref()
                    .and_then(|o| o.tracer_config.as_ref())
                    .and_then(|v| {
                        serde_json::from_value::<cipherbft_execution::OpcodeTracerConfig>(v.clone())
                            .ok()
                    })
                    .unwrap_or_default();

                self.trace_call_with_opcode_tracer(from, to, gas, None, None, None, config)
            }
        }
    }

    async fn trace_call(
        &self,
        from: Option<Address>,
        to: Option<Address>,
        gas: Option<u64>,
        gas_price: Option<U256>,
        value: Option<U256>,
        data: Option<Bytes>,
        _block: BlockNumberOrTag,
        options: Option<cipherbft_execution::TraceOptions>,
    ) -> RpcResult<cipherbft_execution::TraceResult> {
        debug!(
            "EvmDebugExecutionApi::trace_call(from={:?}, to={:?}, gas={:?}, data_len={:?})",
            from,
            to,
            gas,
            data.as_ref().map(|d| d.len())
        );

        // Determine tracer type from options
        let tracer_type = options.as_ref().and_then(|o| o.tracer.as_deref());

        match tracer_type {
            Some("callTracer") => {
                // Parse callTracer config
                let config = options
                    .as_ref()
                    .and_then(|o| o.tracer_config.as_ref())
                    .and_then(|v| {
                        serde_json::from_value::<cipherbft_execution::CallTracerConfig>(v.clone())
                            .ok()
                    })
                    .unwrap_or_default();

                self.trace_call_with_call_tracer(from, to, gas, gas_price, value, data, config)
            }
            _ => {
                // Default to opcode tracer (struct logs)
                let config = options
                    .as_ref()
                    .and_then(|o| o.tracer_config.as_ref())
                    .and_then(|v| {
                        serde_json::from_value::<cipherbft_execution::OpcodeTracerConfig>(v.clone())
                            .ok()
                    })
                    .unwrap_or_default();

                self.trace_call_with_opcode_tracer(from, to, gas, gas_price, value, data, config)
            }
        }
    }

    async fn trace_block(
        &self,
        block: BlockNumberOrTag,
        options: Option<cipherbft_execution::TraceOptions>,
    ) -> RpcResult<Vec<cipherbft_execution::TraceResult>> {
        debug!("EvmDebugExecutionApi::trace_block(block={:?})", block);

        // Check if we have storage configured
        let (block_store, receipt_store) = match (&self.block_store, &self.receipt_store) {
            (Some(b), Some(r)) => (b, r),
            _ => {
                return Err(RpcError::MethodNotSupported(
                    "debug_traceBlockByNumber/Hash requires storage configuration. \
                     Use EvmDebugExecutionApi::with_storage() or use debug_traceCall instead."
                        .to_string(),
                ));
            }
        };

        // Resolve block number
        let block_number = match block {
            BlockNumberOrTag::Number(n) => n,
            BlockNumberOrTag::Latest
            | BlockNumberOrTag::Safe
            | BlockNumberOrTag::Finalized
            | BlockNumberOrTag::Pending => self.latest_block.load(Ordering::SeqCst),
            BlockNumberOrTag::Earliest => 0,
        };

        // 1. Get the block
        let block_data = block_store
            .get_block_by_number(block_number)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to get block: {}", e)))?
            .ok_or_else(|| RpcError::NotFound(format!("Block {} not found", block_number)))?;

        // 2. Get all receipts for the block
        let receipts = receipt_store
            .get_receipts_by_block(block_number)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to get receipts: {}", e)))?;

        debug!(
            "Tracing block {} with {} transactions",
            block_number,
            receipts.len()
        );

        // 3. Trace each transaction
        let mut traces = Vec::with_capacity(receipts.len());

        for receipt in receipts {
            let from = Some(Address::from_slice(&receipt.from));
            let to = receipt.to.map(|t| Address::from_slice(&t));
            let gas = Some(receipt.gas_used);

            // Determine tracer type
            let tracer_type = options.as_ref().and_then(|o| o.tracer.as_deref());

            let trace = match tracer_type {
                Some("callTracer") => {
                    let config = options
                        .as_ref()
                        .and_then(|o| o.tracer_config.as_ref())
                        .and_then(|v| {
                            serde_json::from_value::<cipherbft_execution::CallTracerConfig>(
                                v.clone(),
                            )
                            .ok()
                        })
                        .unwrap_or_default();

                    self.trace_call_with_call_tracer(from, to, gas, None, None, None, config)?
                }
                _ => {
                    let config = options
                        .as_ref()
                        .and_then(|o| o.tracer_config.as_ref())
                        .and_then(|v| {
                            serde_json::from_value::<cipherbft_execution::OpcodeTracerConfig>(
                                v.clone(),
                            )
                            .ok()
                        })
                        .unwrap_or_default();

                    self.trace_call_with_opcode_tracer(from, to, gas, None, None, None, config)?
                }
            };

            traces.push(trace);
        }

        // Suppress unused warning for block_data (used for context in full implementation)
        let _ = block_data;

        Ok(traces)
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

    // ===== Log conversion helper tests =====

    #[test]
    fn test_rpc_filter_to_storage_filter_default() {
        use cipherbft_execution::database::InMemoryProvider;

        let filter = Filter::default();
        let storage_filter =
            MdbxRpcStorage::<InMemoryProvider>::rpc_filter_to_storage_filter(&filter);

        assert!(storage_filter.from_block.is_none());
        assert!(storage_filter.to_block.is_none());
        assert!(storage_filter.block_hash.is_none());
        assert!(storage_filter.addresses.is_empty());
        // All topics should be None (match any)
        for topic in &storage_filter.topics {
            assert!(topic.is_none());
        }
    }

    #[test]
    fn test_rpc_filter_to_storage_filter_with_block_range() {
        use cipherbft_execution::database::InMemoryProvider;

        let filter = Filter::new().from_block(100u64).to_block(200u64);
        let storage_filter =
            MdbxRpcStorage::<InMemoryProvider>::rpc_filter_to_storage_filter(&filter);

        assert_eq!(storage_filter.from_block, Some(100));
        assert_eq!(storage_filter.to_block, Some(200));
        assert!(storage_filter.block_hash.is_none());
    }

    #[test]
    fn test_rpc_filter_to_storage_filter_with_addresses() {
        use cipherbft_execution::database::InMemoryProvider;

        let addr1 = Address::repeat_byte(0x11);
        let addr2 = Address::repeat_byte(0x22);

        let filter = Filter::new().address(vec![addr1, addr2]);
        let storage_filter =
            MdbxRpcStorage::<InMemoryProvider>::rpc_filter_to_storage_filter(&filter);

        assert_eq!(storage_filter.addresses.len(), 2);
        assert!(storage_filter.addresses.contains(&addr1.0 .0));
        assert!(storage_filter.addresses.contains(&addr2.0 .0));
    }

    #[test]
    fn test_rpc_filter_to_storage_filter_with_topics() {
        use cipherbft_execution::database::InMemoryProvider;

        let topic0 = B256::repeat_byte(0xAA);
        let topic1 = B256::repeat_byte(0xBB);

        let filter = Filter::new()
            .event_signature(topic0) // topic0
            .topic1(topic1); // topic1

        let storage_filter =
            MdbxRpcStorage::<InMemoryProvider>::rpc_filter_to_storage_filter(&filter);

        // Should have 4 topic positions
        assert_eq!(storage_filter.topics.len(), 4);

        // topic0 should match the event signature
        assert!(storage_filter.topics[0].is_some());
        let t0 = storage_filter.topics[0].as_ref().unwrap();
        assert!(t0.contains(&topic0.0));

        // topic1 should match
        assert!(storage_filter.topics[1].is_some());
        let t1 = storage_filter.topics[1].as_ref().unwrap();
        assert!(t1.contains(&topic1.0));

        // topic2 and topic3 should be None (match any)
        assert!(storage_filter.topics[2].is_none());
        assert!(storage_filter.topics[3].is_none());
    }

    #[test]
    fn test_stored_log_to_rpc_log() {
        use cipherbft_execution::database::InMemoryProvider;

        let stored = StoredLog {
            address: [0x11; 20],
            topics: vec![[0xAA; 32], [0xBB; 32]],
            data: vec![1, 2, 3, 4],
            block_number: 12345,
            block_hash: [0x01; 32],
            transaction_hash: [0x02; 32],
            transaction_index: 5,
            log_index: 10,
            removed: false,
        };

        let rpc_log = MdbxRpcStorage::<InMemoryProvider>::stored_log_to_rpc_log(stored);

        // Check address
        assert_eq!(rpc_log.address(), Address::from([0x11; 20]));

        // Check topics
        let topics = rpc_log.topics();
        assert_eq!(topics.len(), 2);
        assert_eq!(topics[0], B256::from([0xAA; 32]));
        assert_eq!(topics[1], B256::from([0xBB; 32]));

        // Check data
        assert_eq!(rpc_log.data().data.as_ref(), &[1u8, 2, 3, 4]);

        // Check metadata
        assert_eq!(rpc_log.block_number, Some(12345));
        assert_eq!(rpc_log.block_hash, Some(B256::from([0x01; 32])));
        assert_eq!(rpc_log.transaction_hash, Some(B256::from([0x02; 32])));
        assert_eq!(rpc_log.transaction_index, Some(5));
        assert_eq!(rpc_log.log_index, Some(10));
        assert!(!rpc_log.removed);
    }

    #[test]
    fn test_stored_log_to_rpc_log_removed() {
        use cipherbft_execution::database::InMemoryProvider;

        let stored = StoredLog {
            address: [0x00; 20],
            topics: vec![],
            data: vec![],
            block_number: 1,
            block_hash: [0x00; 32],
            transaction_hash: [0x00; 32],
            transaction_index: 0,
            log_index: 0,
            removed: true, // Removed due to reorg
        };

        let rpc_log = MdbxRpcStorage::<InMemoryProvider>::stored_log_to_rpc_log(stored);

        assert!(rpc_log.removed);
        assert!(rpc_log.topics().is_empty());
        assert!(rpc_log.data().data.is_empty());
    }
}
