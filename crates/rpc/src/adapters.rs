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
use alloy_rpc_types_eth::{Block, Filter, Log, Transaction, TransactionReceipt};
use async_trait::async_trait;
use cipherbft_execution::database::Provider;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, trace};

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
// Stub Implementations (for testing and features not yet integrated)
// ============================================================================

/// Stub RPC storage adapter.
///
/// This adapter provides placeholder implementations for RPC storage operations.
/// Used for testing or when the real storage backend is not available.
pub struct StubRpcStorage {
    /// Latest block number (for testing).
    latest_block: u64,
    /// Chain ID (reserved for future use).
    #[allow(dead_code)]
    chain_id: u64,
}

impl StubRpcStorage {
    /// Create a new stub storage adapter.
    pub fn new(chain_id: u64) -> Self {
        Self {
            latest_block: 0,
            chain_id,
        }
    }

    /// Set the latest block number (for testing).
    pub fn set_latest_block(&mut self, block: u64) {
        self.latest_block = block;
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
        Ok(self.latest_block)
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
