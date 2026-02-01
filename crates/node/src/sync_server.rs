//! Snap Sync Server - Handles incoming P2P snap sync requests
//!
//! This module implements server-side handlers for the snap sync protocol.
//! When peers request state data (accounts, storage, blocks), this server
//! responds with data from local storage.
//!
//! # Protocol
//!
//! Uses `/cipherbft/snap/1.0.0` request-response protocol.
//!
//! # Handlers
//!
//! - `GetStatus` -> `Status`: Returns local tip and available snapshots
//! - `GetAccountRange` -> `AccountRange`: Returns accounts in address range
//! - `GetStorageRange` -> `StorageRange`: Returns storage slots for an account
//! - `GetBlocks` -> `Blocks`: Returns blocks in height range

use alloy_primitives::{Address, Bytes, B256, U256};
use cipherbft_storage::{Block, BlockStore, EvmStore, SyncStore};
use cipherbft_sync::protocol::{
    AccountData, AccountRangeRequest, AccountRangeResponse, BlockRangeRequest, BlockRangeResponse,
    SnapSyncMessage, SnapshotInfo, StatusResponse, StorageRangeRequest, StorageRangeResponse,
    MAX_ACCOUNTS_PER_RESPONSE, MAX_BLOCKS_PER_RESPONSE, MAX_STORAGE_PER_RESPONSE,
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Snap sync server that handles incoming requests from peers.
///
/// This server queries local storage to serve state data to syncing peers.
/// It holds references to the various storage backends needed to respond
/// to different request types.
pub struct SnapSyncServer<B, E, S>
where
    B: BlockStore,
    E: EvmStore,
    S: SyncStore,
{
    /// Block storage for serving block data
    block_store: Arc<B>,
    /// EVM state storage for accounts and storage slots
    evm_store: Arc<E>,
    /// Sync storage for snapshot metadata
    sync_store: Arc<S>,
}

impl<B, E, S> SnapSyncServer<B, E, S>
where
    B: BlockStore,
    E: EvmStore,
    S: SyncStore,
{
    /// Create a new snap sync server.
    ///
    /// # Arguments
    ///
    /// * `block_store` - Storage for blocks
    /// * `evm_store` - Storage for EVM accounts and storage
    /// * `sync_store` - Storage for sync snapshots
    pub fn new(block_store: Arc<B>, evm_store: Arc<E>, sync_store: Arc<S>) -> Self {
        Self {
            block_store,
            evm_store,
            sync_store,
        }
    }

    /// Handle an incoming snap sync request and return the response.
    ///
    /// This is the main entry point for processing incoming messages.
    /// It dispatches to the appropriate handler based on message type.
    ///
    /// # Arguments
    ///
    /// * `request` - The incoming snap sync message
    ///
    /// # Returns
    ///
    /// The response message, or None if the request doesn't need a response
    /// (e.g., if it's already a response message).
    pub async fn handle_request(&self, request: SnapSyncMessage) -> Option<SnapSyncMessage> {
        match request {
            SnapSyncMessage::GetStatus => Some(self.handle_get_status().await),
            SnapSyncMessage::GetAccountRange(req) => Some(self.handle_get_account_range(req).await),
            SnapSyncMessage::GetStorageRange(req) => Some(self.handle_get_storage_range(req).await),
            SnapSyncMessage::GetBlocks(req) => Some(self.handle_get_blocks(req).await),
            // Response messages don't need handling - they're for the client side
            SnapSyncMessage::Status(_)
            | SnapSyncMessage::AccountRange(_)
            | SnapSyncMessage::StorageRange(_)
            | SnapSyncMessage::Blocks(_) => None,
        }
    }

    /// Handle GetStatus request.
    ///
    /// Returns the local blockchain tip (height and hash) along with
    /// a list of available snapshot heights for sync.
    async fn handle_get_status(&self) -> SnapSyncMessage {
        debug!("Handling GetStatus request");

        // Get latest block number and hash
        let (tip_height, tip_hash) = match self.block_store.get_latest_block_number().await {
            Ok(Some(height)) => match self.block_store.get_block_by_number(height).await {
                Ok(Some(block)) => (height, B256::from(block.hash)),
                Ok(None) => {
                    warn!("Latest block {} not found in storage", height);
                    (0, B256::ZERO)
                }
                Err(e) => {
                    warn!("Failed to get latest block: {}", e);
                    (0, B256::ZERO)
                }
            },
            Ok(None) => {
                debug!("No blocks in storage, returning genesis state");
                (0, B256::ZERO)
            }
            Err(e) => {
                warn!("Failed to get latest block number: {}", e);
                (0, B256::ZERO)
            }
        };

        // Get available snapshot heights and convert to SnapshotInfo
        let snapshot_heights = match self.sync_store.list_snapshot_heights().await {
            Ok(heights) => heights,
            Err(e) => {
                warn!("Failed to list snapshot heights: {}", e);
                Vec::new()
            }
        };

        // Build full SnapshotInfo for each height
        let mut snapshots = Vec::with_capacity(snapshot_heights.len());
        for height in snapshot_heights {
            // Get snapshot details from sync store
            if let Ok(Some(stored_snapshot)) = self.sync_store.get_snapshot(height).await {
                snapshots.push(SnapshotInfo {
                    height: stored_snapshot.block_number,
                    state_root: B256::from(stored_snapshot.state_root),
                    block_hash: B256::from(stored_snapshot.block_hash),
                });
            }
        }

        debug!(
            tip_height,
            ?tip_hash,
            snapshot_count = snapshots.len(),
            "Returning status"
        );

        SnapSyncMessage::Status(StatusResponse {
            tip_height,
            tip_hash,
            snapshots,
        })
    }

    /// Handle GetAccountRange request.
    ///
    /// Queries accounts from local storage within the specified address range.
    /// Returns accounts along with merkle proofs (currently stubbed).
    async fn handle_get_account_range(&self, req: AccountRangeRequest) -> SnapSyncMessage {
        debug!(
            snapshot_height = req.snapshot_height,
            start = ?req.start_address,
            limit = ?req.limit_address,
            max_accounts = req.max_accounts,
            "Handling GetAccountRange request"
        );

        // Cap the number of accounts to return
        let max_accounts = req.max_accounts.min(MAX_ACCOUNTS_PER_RESPONSE) as usize;

        // Get all accounts from storage and filter by range
        // Note: This is a simplified implementation. A production version would
        // use cursor-based iteration with seek to the start address.
        let accounts_result = self.evm_store.get_all_accounts();

        let (accounts, more) = match accounts_result {
            Ok(all_accounts) => {
                let start_bytes: [u8; 20] = req.start_address.into();
                let limit_bytes: [u8; 20] = req.limit_address.into();

                // Filter accounts within the range
                let mut filtered: Vec<AccountData> = all_accounts
                    .into_iter()
                    .filter(|(addr, _)| *addr >= start_bytes && *addr < limit_bytes)
                    .take(max_accounts + 1) // Take one extra to check if there's more
                    .map(|(addr, account)| AccountData {
                        address: Address::from(addr),
                        nonce: account.nonce,
                        balance: U256::from_be_bytes(account.balance),
                        code_hash: B256::from(account.code_hash),
                        storage_root: B256::from(account.storage_root),
                    })
                    .collect();

                // Check if there are more accounts
                let more = filtered.len() > max_accounts;
                if more {
                    filtered.pop(); // Remove the extra account
                }

                (filtered, more)
            }
            Err(e) => {
                warn!("Failed to get accounts: {}", e);
                (Vec::new(), false)
            }
        };

        debug!(
            accounts_returned = accounts.len(),
            more, "Returning account range"
        );

        // TODO: Generate actual merkle proofs using alloy-trie
        // For now, return empty proof - client should verify against state root
        let proof = Vec::new();

        SnapSyncMessage::AccountRange(AccountRangeResponse {
            request_id: req.request_id,
            accounts,
            proof,
            more,
        })
    }

    /// Handle GetStorageRange request.
    ///
    /// Queries storage slots for a specific account within the slot range.
    /// Returns slots along with merkle proofs (currently stubbed).
    async fn handle_get_storage_range(&self, req: StorageRangeRequest) -> SnapSyncMessage {
        debug!(
            snapshot_height = req.snapshot_height,
            account = ?req.account,
            start_slot = ?req.start_slot,
            limit_slot = ?req.limit_slot,
            max_slots = req.max_slots,
            "Handling GetStorageRange request"
        );

        // Cap the number of slots to return
        let max_slots = req.max_slots.min(MAX_STORAGE_PER_RESPONSE) as usize;

        // Convert account address to bytes
        let account_bytes: [u8; 20] = req.account.into();

        // Get all storage for this account and filter by range
        let storage_result = self.evm_store.get_all_storage(&account_bytes);

        let (slots, more) = match storage_result {
            Ok(all_storage) => {
                let start_bytes: [u8; 32] = req.start_slot.into();
                let limit_bytes: [u8; 32] = req.limit_slot.into();

                // Filter slots within the range
                let mut filtered: Vec<(B256, B256)> = all_storage
                    .into_iter()
                    .filter(|(slot, _)| *slot >= start_bytes && *slot < limit_bytes)
                    .take(max_slots + 1) // Take one extra to check if there's more
                    .map(|(slot, value)| (B256::from(slot), B256::from(value)))
                    .collect();

                // Check if there are more slots
                let more = filtered.len() > max_slots;
                if more {
                    filtered.pop(); // Remove the extra slot
                }

                (filtered, more)
            }
            Err(e) => {
                warn!("Failed to get storage for account {:?}: {}", req.account, e);
                (Vec::new(), false)
            }
        };

        debug!(
            slots_returned = slots.len(),
            more, "Returning storage range"
        );

        // TODO: Generate actual merkle proofs using alloy-trie
        let proof = Vec::new();

        SnapSyncMessage::StorageRange(StorageRangeResponse {
            request_id: req.request_id,
            slots,
            proof,
            more,
        })
    }

    /// Handle GetBlocks request.
    ///
    /// Fetches blocks from storage in the specified height range.
    /// Returns serialized blocks.
    async fn handle_get_blocks(&self, req: BlockRangeRequest) -> SnapSyncMessage {
        debug!(
            start_height = req.start_height,
            count = req.count,
            "Handling GetBlocks request"
        );

        // Cap the number of blocks to return
        let count = req.count.min(MAX_BLOCKS_PER_RESPONSE) as u64;

        let mut blocks = Vec::new();

        for height in req.start_height..(req.start_height + count) {
            match self.block_store.get_block_by_number(height).await {
                Ok(Some(block)) => {
                    // Serialize block to bytes
                    match serialize_block(&block) {
                        Ok(bytes) => blocks.push(bytes),
                        Err(e) => {
                            warn!("Failed to serialize block {}: {}", height, e);
                            break;
                        }
                    }
                }
                Ok(None) => {
                    // No more blocks available
                    debug!("Block {} not found, stopping", height);
                    break;
                }
                Err(e) => {
                    warn!("Failed to get block {}: {}", height, e);
                    break;
                }
            }
        }

        debug!(blocks_returned = blocks.len(), "Returning blocks");

        SnapSyncMessage::Blocks(BlockRangeResponse {
            request_id: req.request_id,
            blocks,
        })
    }
}

/// Serialize a block to bytes for network transmission.
///
/// Uses bincode for efficient serialization.
fn serialize_block(block: &Block) -> Result<Bytes, bincode::Error> {
    let bytes = bincode::serialize(block)?;
    Ok(Bytes::from(bytes))
}

/// Deserialize a block from bytes received over the network.
///
/// Used by the client side to reconstruct blocks from responses.
#[allow(dead_code)]
pub fn deserialize_block(bytes: &[u8]) -> Result<Block, bincode::Error> {
    bincode::deserialize(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbft_storage::{
        EvmAccount, EvmStoreResult, InMemorySyncStore, StoredSyncSnapshot, SyncStore,
    };
    use std::collections::HashMap;
    use std::sync::RwLock;

    /// In-memory block store for testing
    struct TestBlockStore {
        blocks: RwLock<HashMap<u64, Block>>,
    }

    impl TestBlockStore {
        fn new() -> Self {
            Self {
                blocks: RwLock::new(HashMap::new()),
            }
        }

        fn add_block(&self, block: Block) {
            self.blocks.write().unwrap().insert(block.number, block);
        }
    }

    #[async_trait::async_trait]
    impl BlockStore for TestBlockStore {
        async fn put_block(&self, block: &Block) -> cipherbft_storage::BlockStoreResult<()> {
            self.blocks
                .write()
                .unwrap()
                .insert(block.number, block.clone());
            Ok(())
        }

        async fn get_block_by_number(
            &self,
            number: u64,
        ) -> cipherbft_storage::BlockStoreResult<Option<Block>> {
            Ok(self.blocks.read().unwrap().get(&number).cloned())
        }

        async fn get_block_by_hash(
            &self,
            hash: &[u8; 32],
        ) -> cipherbft_storage::BlockStoreResult<Option<Block>> {
            Ok(self
                .blocks
                .read()
                .unwrap()
                .values()
                .find(|b| &b.hash == hash)
                .cloned())
        }

        async fn get_block_number_by_hash(
            &self,
            hash: &[u8; 32],
        ) -> cipherbft_storage::BlockStoreResult<Option<u64>> {
            Ok(self
                .blocks
                .read()
                .unwrap()
                .values()
                .find(|b| &b.hash == hash)
                .map(|b| b.number))
        }

        async fn get_latest_block_number(
            &self,
        ) -> cipherbft_storage::BlockStoreResult<Option<u64>> {
            Ok(self.blocks.read().unwrap().keys().max().copied())
        }

        async fn get_earliest_block_number(
            &self,
        ) -> cipherbft_storage::BlockStoreResult<Option<u64>> {
            Ok(self.blocks.read().unwrap().keys().min().copied())
        }

        async fn has_block(&self, number: u64) -> cipherbft_storage::BlockStoreResult<bool> {
            Ok(self.blocks.read().unwrap().contains_key(&number))
        }

        async fn delete_block(&self, number: u64) -> cipherbft_storage::BlockStoreResult<()> {
            self.blocks.write().unwrap().remove(&number);
            Ok(())
        }
    }

    /// In-memory EVM store for testing
    #[allow(clippy::type_complexity)]
    struct TestEvmStore {
        accounts: RwLock<HashMap<[u8; 20], EvmAccount>>,
        storage: RwLock<HashMap<([u8; 20], [u8; 32]), [u8; 32]>>,
    }

    impl TestEvmStore {
        fn new() -> Self {
            Self {
                accounts: RwLock::new(HashMap::new()),
                storage: RwLock::new(HashMap::new()),
            }
        }

        #[allow(dead_code)]
        fn add_account(&self, address: [u8; 20], account: EvmAccount) {
            self.accounts.write().unwrap().insert(address, account);
        }

        #[allow(dead_code)]
        fn add_storage(&self, address: [u8; 20], slot: [u8; 32], value: [u8; 32]) {
            self.storage.write().unwrap().insert((address, slot), value);
        }
    }

    impl EvmStore for TestEvmStore {
        fn get_account(&self, address: &[u8; 20]) -> EvmStoreResult<Option<EvmAccount>> {
            Ok(self.accounts.read().unwrap().get(address).cloned())
        }

        fn set_account(&self, address: &[u8; 20], account: EvmAccount) -> EvmStoreResult<()> {
            self.accounts.write().unwrap().insert(*address, account);
            Ok(())
        }

        fn delete_account(&self, address: &[u8; 20]) -> EvmStoreResult<()> {
            self.accounts.write().unwrap().remove(address);
            Ok(())
        }

        fn get_code(
            &self,
            _code_hash: &[u8; 32],
        ) -> EvmStoreResult<Option<cipherbft_storage::EvmBytecode>> {
            Ok(None)
        }

        fn set_code(
            &self,
            _code_hash: &[u8; 32],
            _bytecode: cipherbft_storage::EvmBytecode,
        ) -> EvmStoreResult<()> {
            Ok(())
        }

        fn get_storage(&self, address: &[u8; 20], slot: &[u8; 32]) -> EvmStoreResult<[u8; 32]> {
            Ok(self
                .storage
                .read()
                .unwrap()
                .get(&(*address, *slot))
                .copied()
                .unwrap_or([0u8; 32]))
        }

        fn set_storage(
            &self,
            address: &[u8; 20],
            slot: &[u8; 32],
            value: [u8; 32],
        ) -> EvmStoreResult<()> {
            self.storage
                .write()
                .unwrap()
                .insert((*address, *slot), value);
            Ok(())
        }

        fn get_block_hash(&self, _number: u64) -> EvmStoreResult<Option<[u8; 32]>> {
            Ok(None)
        }

        fn set_block_hash(&self, _number: u64, _hash: [u8; 32]) -> EvmStoreResult<()> {
            Ok(())
        }

        fn get_all_accounts(&self) -> EvmStoreResult<Vec<([u8; 20], EvmAccount)>> {
            let accounts = self.accounts.read().unwrap();
            let mut result: Vec<_> = accounts.iter().map(|(k, v)| (*k, v.clone())).collect();
            result.sort_by_key(|(k, _)| *k);
            Ok(result)
        }

        fn get_all_storage(&self, address: &[u8; 20]) -> EvmStoreResult<Vec<([u8; 32], [u8; 32])>> {
            let storage = self.storage.read().unwrap();
            let mut result: Vec<_> = storage
                .iter()
                .filter(|((addr, _), _)| addr == address)
                .map(|((_, slot), value)| (*slot, *value))
                .collect();
            result.sort_by_key(|(k, _)| *k);
            Ok(result)
        }

        fn get_current_block(&self) -> EvmStoreResult<Option<u64>> {
            Ok(None)
        }

        fn set_current_block(&self, _block_number: u64) -> EvmStoreResult<()> {
            Ok(())
        }
    }

    fn make_test_block(number: u64) -> Block {
        let mut hash = [0u8; 32];
        hash[0] = (number & 0xff) as u8;
        hash[1] = ((number >> 8) & 0xff) as u8;

        Block {
            hash,
            number,
            parent_hash: [number.saturating_sub(1) as u8; 32],
            ommers_hash: [0u8; 32],
            beneficiary: [1u8; 20],
            state_root: [2u8; 32],
            transactions_root: [3u8; 32],
            receipts_root: [4u8; 32],
            logs_bloom: vec![0u8; 256],
            difficulty: [0u8; 32],
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1700000000 + number,
            extra_data: vec![],
            mix_hash: [5u8; 32],
            nonce: [0u8; 8],
            base_fee_per_gas: Some(1_000_000_000),
            transaction_hashes: vec![],
            transaction_count: 0,
            total_difficulty: [0u8; 32],
            size: 500,
        }
    }

    #[tokio::test]
    async fn test_handle_get_status() {
        let block_store = Arc::new(TestBlockStore::new());
        let evm_store = Arc::new(TestEvmStore::new());
        let sync_store = Arc::new(InMemorySyncStore::new());

        // Add some blocks
        block_store.add_block(make_test_block(1));
        block_store.add_block(make_test_block(2));
        block_store.add_block(make_test_block(3));

        // Add a snapshot
        sync_store
            .put_snapshot(StoredSyncSnapshot::new(
                10000, [0xab; 32], [0xcd; 32], 123456,
            ))
            .await
            .unwrap();

        let server = SnapSyncServer::new(block_store, evm_store, sync_store);

        let response = server.handle_request(SnapSyncMessage::GetStatus).await;

        match response {
            Some(SnapSyncMessage::Status(status)) => {
                assert_eq!(status.tip_height, 3);
                // Verify we got one snapshot with correct data
                assert_eq!(status.snapshots.len(), 1);
                assert_eq!(status.snapshots[0].height, 10000);
                assert_eq!(status.snapshots[0].state_root, B256::from([0xcd; 32]));
                assert_eq!(status.snapshots[0].block_hash, B256::from([0xab; 32]));
            }
            _ => panic!("Expected Status response"),
        }
    }

    #[tokio::test]
    async fn test_handle_get_blocks() {
        let block_store = Arc::new(TestBlockStore::new());
        let evm_store = Arc::new(TestEvmStore::new());
        let sync_store = Arc::new(InMemorySyncStore::new());

        // Add blocks
        for i in 1..=10 {
            block_store.add_block(make_test_block(i));
        }

        let server = SnapSyncServer::new(block_store, evm_store, sync_store);

        let request = SnapSyncMessage::GetBlocks(BlockRangeRequest {
            request_id: 42,
            start_height: 5,
            count: 3,
        });

        let response = server.handle_request(request).await;

        match response {
            Some(SnapSyncMessage::Blocks(blocks_response)) => {
                assert_eq!(blocks_response.blocks.len(), 3);
                // Verify we can deserialize the blocks
                for (i, block_bytes) in blocks_response.blocks.iter().enumerate() {
                    let block = deserialize_block(block_bytes).unwrap();
                    assert_eq!(block.number, 5 + i as u64);
                }
            }
            _ => panic!("Expected Blocks response"),
        }
    }

    #[tokio::test]
    async fn test_response_messages_return_none() {
        let block_store = Arc::new(TestBlockStore::new());
        let evm_store = Arc::new(TestEvmStore::new());
        let sync_store = Arc::new(InMemorySyncStore::new());

        let server = SnapSyncServer::new(block_store, evm_store, sync_store);

        // Response messages should return None (no response needed)
        let status_response = SnapSyncMessage::Status(StatusResponse {
            tip_height: 100,
            tip_hash: B256::ZERO,
            snapshots: vec![],
        });

        assert!(server.handle_request(status_response).await.is_none());
    }
}
