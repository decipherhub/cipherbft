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
//! # Future Work
//!
//! These adapters will be fully implemented when:
//! - Block/Transaction storage is added to cipherbft-storage
//! - Mempool integration is completed
//! - Execution layer (revm) integration is finalized

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types_eth::{Block, Filter, Log, Transaction, TransactionReceipt};
use async_trait::async_trait;
use tracing::{debug, trace};

use crate::error::RpcResult;
use crate::traits::{
    BlockNumberOrTag, ExecutionApi, MempoolApi, NetworkApi, RpcStorage, SyncStatus,
};

/// Stub RPC storage adapter.
///
/// This adapter provides placeholder implementations for RPC storage operations.
/// Replace with actual storage integration when block/tx storage is available.
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
        // Return None for now - no blocks stored
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
        // For now, always report as synced
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
