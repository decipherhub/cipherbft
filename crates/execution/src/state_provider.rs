//! StateProviderFactory implementation for CipherBFT execution layer.
//!
//! This module provides Reth-compatible state provider traits for integration
//! with the transaction pool and RPC layer.

use std::sync::Arc;

use alloy_eips::{BlockNumHash, BlockNumberOrTag};
use alloy_primitives::{Address, BlockHash, BlockNumber, Bytes, StorageKey, StorageValue, B256, U256};
use parking_lot::RwLock;
use reth_chainspec::{ChainInfo, ChainSpec, ChainSpecProvider};
use reth_execution_types::ExecutionOutcome;
use reth_primitives_traits::Bytecode;
use reth_storage_api::{
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, BytecodeReader,
    HashedPostStateProvider, StateProofProvider, StateProvider, StateProviderBox,
    StateProviderFactory, StateReader, StateRootProvider, StorageRootProvider,
};
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use reth_trie_common::{
    updates::TrieUpdates, AccountProof, HashedPostState, HashedStorage, KeccakKeyHasher, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput, Nibbles,
};

use crate::{
    database::Provider,
    mpt::{compute_state_root, compute_storage_root},
    state::StateManager,
    Account,
};

/// Block tracker for maintaining block metadata.
#[derive(Debug, Default)]
pub struct BlockTracker {
    latest_block_number: RwLock<u64>,
    latest_block_hash: RwLock<B256>,
    block_hashes: RwLock<std::collections::BTreeMap<u64, B256>>,
}

impl BlockTracker {
    /// Create a new block tracker.
    pub fn new() -> Self { Self::default() }

    /// Update the latest block.
    pub fn set_latest(&self, number: u64, hash: B256) {
        *self.latest_block_number.write() = number;
        *self.latest_block_hash.write() = hash;
        self.block_hashes.write().insert(number, hash);
    }

    /// Get the latest block number.
    pub fn latest_number(&self) -> u64 { *self.latest_block_number.read() }

    /// Get the latest block hash.
    pub fn latest_hash(&self) -> B256 { *self.latest_block_hash.read() }

    /// Get block hash by number.
    pub fn hash_by_number(&self, number: u64) -> Option<B256> {
        self.block_hashes.read().get(&number).copied()
    }

    /// Get block number by hash.
    pub fn number_by_hash(&self, hash: B256) -> Option<u64> {
        self.block_hashes.read().iter().find(|(_, h)| **h == hash).map(|(n, _)| *n)
    }

    /// Get canonical hashes in a range.
    pub fn canonical_hashes_range(&self, start: BlockNumber, end: BlockNumber) -> Vec<B256> {
        let hashes = self.block_hashes.read();
        (start..end).filter_map(|n| hashes.get(&n).copied()).collect()
    }
}

/// State provider for a specific block height.
pub struct CipherBftStateProvider<P: Provider> {
    provider: Arc<P>,
    state_manager: Arc<StateManager<P>>,
    #[allow(dead_code)]
    block_number: u64,
    #[allow(dead_code)]
    block_hash: B256,
}

impl<P: Provider> std::fmt::Debug for CipherBftStateProvider<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherBftStateProvider")
            .field("block_number", &self.block_number)
            .field("block_hash", &self.block_hash)
            .finish_non_exhaustive()
    }
}

impl<P: Provider> CipherBftStateProvider<P> {
    /// Create a new state provider.
    pub fn new(provider: Arc<P>, state_manager: Arc<StateManager<P>>, block_number: u64, block_hash: B256) -> Self {
        Self { provider, state_manager, block_number, block_hash }
    }

    fn to_reth_account(account: &Account) -> reth_primitives_traits::Account {
        reth_primitives_traits::Account {
            nonce: account.nonce,
            balance: account.balance,
            bytecode_hash: if account.code_hash == B256::ZERO { None } else { Some(account.code_hash) },
        }
    }

    fn map_err(e: crate::error::ExecutionError) -> ProviderError {
        ProviderError::Database(reth_storage_errors::db::DatabaseError::Other(e.to_string()))
    }
}

impl<P: Provider> BlockHashReader for CipherBftStateProvider<P> {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<BlockHash>> {
        self.provider.get_block_hash(number).map_err(Self::map_err)
    }
    fn canonical_hashes_range(&self, _start: BlockNumber, _end: BlockNumber) -> ProviderResult<Vec<B256>> {
        // Note: State provider operates at a single block height and doesn't track historical hashes.
        // Use BlockTracker via the factory for canonical hash queries.
        Ok(vec![])
    }
}

impl<P: Provider> AccountReader for CipherBftStateProvider<P> {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<reth_primitives_traits::Account>> {
        match self.provider.get_account(*address) {
            Ok(Some(account)) => Ok(Some(Self::to_reth_account(&account))),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }
}

impl<P: Provider> BytecodeReader for CipherBftStateProvider<P> {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        if *code_hash == crate::rlp::KECCAK_EMPTY || *code_hash == B256::ZERO {
            return Ok(None);
        }
        match self.provider.get_code(*code_hash) {
            Ok(Some(bytecode)) => Ok(Some(Bytecode::new_raw(bytecode.bytecode().clone()))),
            Ok(None) => Ok(None),
            Err(e) => Err(Self::map_err(e)),
        }
    }
}

impl<P: Provider> StateRootProvider for CipherBftStateProvider<P> {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        if hashed_state.accounts.is_empty() && hashed_state.storages.is_empty() {
            return Ok(self.state_manager.current_state_root());
        }
        let accounts = self.provider.get_all_accounts().map_err(Self::map_err)?;
        let provider_clone = Arc::clone(&self.provider);
        let storage_getter = move |addr: Address| provider_clone.get_all_storage(addr);
        compute_state_root(&accounts, storage_getter).map_err(Self::map_err)
    }

    fn state_root_from_nodes(&self, _input: TrieInput) -> ProviderResult<B256> {
        Ok(self.state_manager.current_state_root())
    }

    fn state_root_with_updates(&self, hashed_state: HashedPostState) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.state_root(hashed_state)?, TrieUpdates::default()))
    }

    fn state_root_from_nodes_with_updates(&self, input: TrieInput) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.state_root_from_nodes(input)?, TrieUpdates::default()))
    }
}

impl<P: Provider> StorageRootProvider for CipherBftStateProvider<P> {
    fn storage_root(&self, address: Address, _hashed_storage: HashedStorage) -> ProviderResult<B256> {
        let storage = self.provider.get_all_storage(address).map_err(Self::map_err)?;
        Ok(compute_storage_root(&storage))
    }

    fn storage_proof(&self, address: Address, slot: B256, _hashed_storage: HashedStorage) -> ProviderResult<StorageProof> {
        let value = self.provider.get_storage(address, slot.into()).map_err(Self::map_err)?;
        Ok(StorageProof {
            key: slot,
            nibbles: Nibbles::unpack(alloy_primitives::keccak256(slot)),
            value,
            proof: vec![],
        })
    }

    fn storage_multiproof(&self, address: Address, _slots: &[B256], hashed_storage: HashedStorage) -> ProviderResult<StorageMultiProof> {
        Ok(StorageMultiProof {
            root: self.storage_root(address, hashed_storage)?,
            subtree: Default::default(),
            branch_node_masks: Default::default(),
        })
    }
}

impl<P: Provider> StateProofProvider for CipherBftStateProvider<P> {
    fn proof(&self, _input: TrieInput, address: Address, slots: &[B256]) -> ProviderResult<AccountProof> {
        let accounts = self.provider.get_all_accounts().map_err(Self::map_err)?;
        let account = self.provider.get_account(address).map_err(Self::map_err)?;
        let provider_clone = Arc::clone(&self.provider);
        let storage_getter = move |addr: Address| provider_clone.get_all_storage(addr);
        let storage_keys: Vec<U256> = slots.iter().map(|s| (*s).into()).collect();

        let proof = crate::proof::generate_account_proof(&accounts, storage_getter, address, storage_keys)
            .map_err(Self::map_err)?;

        Ok(AccountProof {
            address,
            info: account.map(|a| Self::to_reth_account(&a)),
            proof: proof.account_proof,
            storage_root: proof.storage_hash,
            storage_proofs: proof.storage_proof.into_iter().map(|sp| {
                StorageProof {
                    key: sp.key.into(),
                    nibbles: Nibbles::unpack(alloy_primitives::keccak256(B256::from(sp.key))),
                    value: sp.value,
                    proof: sp.proof,
                }
            }).collect(),
        })
    }

    fn multiproof(&self, _input: TrieInput, _targets: MultiProofTargets) -> ProviderResult<MultiProof> {
        Ok(MultiProof {
            account_subtree: Default::default(),
            storages: Default::default(),
            branch_node_masks: Default::default(),
        })
    }

    fn witness(&self, _input: TrieInput, _target: HashedPostState) -> ProviderResult<Vec<Bytes>> {
        Ok(vec![])
    }
}

impl<P: Provider> HashedPostStateProvider for CipherBftStateProvider<P> {
    fn hashed_post_state(&self, bundle_state: &revm::database::BundleState) -> HashedPostState {
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state())
    }
}

impl<P: Provider + 'static> StateProvider for CipherBftStateProvider<P> {
    fn storage(&self, account: Address, storage_key: StorageKey) -> ProviderResult<Option<StorageValue>> {
        let value = self.provider.get_storage(account, storage_key.into()).map_err(Self::map_err)?;
        if value.is_zero() { Ok(None) } else { Ok(Some(value)) }
    }
}

impl<P: Provider + 'static> StateReader for CipherBftStateProvider<P> {
    type Receipt = alloy_consensus::Receipt;
    fn get_state(&self, _block: BlockNumber) -> ProviderResult<Option<ExecutionOutcome<Self::Receipt>>> {
        // TODO: Implement execution outcome retrieval for historical blocks if needed.
        // Currently not required for mempool validation (primary use case).
        Ok(None)
    }
}

// =============================================================================
// CipherBftStateProviderFactory
// =============================================================================

/// Factory for creating state providers at different block heights.
pub struct CipherBftStateProviderFactory<P: Provider> {
    provider: Arc<P>,
    state_manager: Arc<StateManager<P>>,
    block_tracker: Arc<BlockTracker>,
    chain_spec: Arc<ChainSpec>,
}

impl<P: Provider> std::fmt::Debug for CipherBftStateProviderFactory<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherBftStateProviderFactory")
            .field("block_tracker", &self.block_tracker)
            .finish_non_exhaustive()
    }
}

impl<P: Provider + 'static> CipherBftStateProviderFactory<P> {
    /// Create a new state provider factory.
    pub fn new(
        provider: Arc<P>,
        state_manager: Arc<StateManager<P>>,
        block_tracker: Arc<BlockTracker>,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        Self { provider, state_manager, block_tracker, chain_spec }
    }

    /// Create with default chain spec for testing.
    pub fn new_with_defaults(provider: Arc<P>, state_manager: Arc<StateManager<P>>) -> Self {
        Self {
            provider,
            state_manager,
            block_tracker: Arc::new(BlockTracker::new()),
            chain_spec: reth_chainspec::MAINNET.clone(),
        }
    }

    /// Get a reference to the block tracker.
    pub fn block_tracker(&self) -> &Arc<BlockTracker> { &self.block_tracker }

    /// Get a reference to the provider.
    pub fn provider(&self) -> &Arc<P> { &self.provider }

    /// Get a reference to the state manager.
    pub fn state_manager(&self) -> &Arc<StateManager<P>> { &self.state_manager }

    fn create_provider(&self, block_number: u64, block_hash: B256) -> StateProviderBox {
        Box::new(CipherBftStateProvider::new(
            Arc::clone(&self.provider),
            Arc::clone(&self.state_manager),
            block_number,
            block_hash,
        ))
    }
}

impl<P: Provider + 'static> ChainSpecProvider for CipherBftStateProviderFactory<P> {
    type ChainSpec = ChainSpec;
    fn chain_spec(&self) -> Arc<Self::ChainSpec> { Arc::clone(&self.chain_spec) }
}

impl<P: Provider + 'static> BlockHashReader for CipherBftStateProviderFactory<P> {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<BlockHash>> {
        Ok(self.block_tracker.hash_by_number(number))
    }
    fn canonical_hashes_range(&self, start: BlockNumber, end: BlockNumber) -> ProviderResult<Vec<B256>> {
        Ok(self.block_tracker.canonical_hashes_range(start, end))
    }
}

impl<P: Provider + 'static> BlockNumReader for CipherBftStateProviderFactory<P> {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        Ok(ChainInfo {
            best_hash: self.block_tracker.latest_hash(),
            best_number: self.block_tracker.latest_number(),
        })
    }
    fn best_block_number(&self) -> ProviderResult<BlockNumber> { Ok(self.block_tracker.latest_number()) }
    fn last_block_number(&self) -> ProviderResult<BlockNumber> { Ok(self.block_tracker.latest_number()) }
    fn block_number(&self, hash: B256) -> ProviderResult<Option<BlockNumber>> {
        Ok(self.block_tracker.number_by_hash(hash))
    }
}

impl<P: Provider + 'static> BlockIdReader for CipherBftStateProviderFactory<P> {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> { Ok(None) }
    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(BlockNumHash::new(self.block_tracker.latest_number(), self.block_tracker.latest_hash())))
    }
    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(BlockNumHash::new(self.block_tracker.latest_number(), self.block_tracker.latest_hash())))
    }
}

impl<P: Provider + 'static> StateProviderFactory for CipherBftStateProviderFactory<P> {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        Ok(self.create_provider(self.block_tracker.latest_number(), self.block_tracker.latest_hash()))
    }

    fn state_by_block_number_or_tag(&self, number_or_tag: BlockNumberOrTag) -> ProviderResult<StateProviderBox> {
        match number_or_tag {
            BlockNumberOrTag::Latest | BlockNumberOrTag::Pending |
            BlockNumberOrTag::Finalized | BlockNumberOrTag::Safe => self.latest(),
            BlockNumberOrTag::Earliest => {
                let hash = self.block_tracker.hash_by_number(0).unwrap_or(B256::ZERO);
                Ok(self.create_provider(0, hash))
            }
            BlockNumberOrTag::Number(n) => self.history_by_block_number(n),
        }
    }

    fn history_by_block_number(&self, block: BlockNumber) -> ProviderResult<StateProviderBox> {
        let latest = self.block_tracker.latest_number();
        if block > latest {
            // Note: Using StateAtBlockPruned for "block not yet available" since there's no
            // exact match in reth's error types. Semantically close to "state unavailable".
            return Err(ProviderError::StateAtBlockPruned(block));
        }
        let hash = self.block_tracker.hash_by_number(block).unwrap_or(B256::ZERO);
        Ok(self.create_provider(block, hash))
    }

    fn history_by_block_hash(&self, block_hash: BlockHash) -> ProviderResult<StateProviderBox> {
        let number = self.block_tracker.number_by_hash(block_hash)
            .ok_or(ProviderError::BlockHashNotFound(block_hash))?;
        self.history_by_block_number(number)
    }

    fn state_by_block_hash(&self, block_hash: BlockHash) -> ProviderResult<StateProviderBox> {
        self.history_by_block_hash(block_hash)
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> { self.latest() }
    fn pending_state_by_hash(&self, _block_hash: B256) -> ProviderResult<Option<StateProviderBox>> { Ok(None) }
    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> { Ok(None) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::InMemoryProvider;

    // Note: InMemoryProvider uses Arc<DashMap<...>> internally, so clones share state.
    // This allows StateManager and Factory to see the same underlying data.
    fn create_test_factory() -> CipherBftStateProviderFactory<InMemoryProvider> {
        let provider = InMemoryProvider::new();
        let state_manager = Arc::new(StateManager::new(provider.clone()));
        CipherBftStateProviderFactory::new_with_defaults(Arc::new(provider), state_manager)
    }

    #[test]
    fn test_block_tracker_operations() {
        let tracker = BlockTracker::new();
        assert_eq!(tracker.latest_number(), 0);
        assert_eq!(tracker.latest_hash(), B256::ZERO);

        let hash = B256::repeat_byte(0x01);
        tracker.set_latest(1, hash);

        assert_eq!(tracker.latest_number(), 1);
        assert_eq!(tracker.latest_hash(), hash);
        assert_eq!(tracker.hash_by_number(1), Some(hash));
        assert_eq!(tracker.number_by_hash(hash), Some(1));
    }

    #[test]
    fn test_factory_creation() {
        let factory = create_test_factory();
        assert_eq!(factory.block_tracker().latest_number(), 0);
    }

    #[test]
    fn test_latest_provider() {
        let factory = create_test_factory();
        let provider = factory.latest().unwrap();
        let account = provider.basic_account(&Address::ZERO).unwrap();
        assert!(account.is_none());
    }

    #[test]
    fn test_chain_spec_provider() {
        let factory = create_test_factory();
        let spec = factory.chain_spec();
        assert!(spec.chain().id() > 0);
    }

    #[test]
    fn test_block_id_reader() {
        let factory = create_test_factory();
        assert!(factory.safe_block_num_hash().unwrap().is_some());
        assert!(factory.finalized_block_num_hash().unwrap().is_some());
        assert!(factory.pending_block_num_hash().unwrap().is_none());
    }

    #[test]
    fn test_account_nonce_retrieval() {
        let provider = InMemoryProvider::new();
        let address = Address::repeat_byte(0x42);
        let account = Account {
            nonce: 5,
            balance: U256::from(1000),
            code_hash: B256::ZERO,
            storage_root: B256::ZERO,
        };
        provider.set_account(address, account).unwrap();

        let state_manager = Arc::new(StateManager::new(provider.clone()));
        let factory = CipherBftStateProviderFactory::new_with_defaults(Arc::new(provider), state_manager);
        let state_provider = factory.latest().unwrap();
        let retrieved = state_provider.basic_account(&address).unwrap();

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().nonce, 5);
    }

    #[test]
    fn test_storage_retrieval() {
        let provider = InMemoryProvider::new();
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(1);
        let value = U256::from(42);
        provider.set_storage(address, slot, value).unwrap();

        let state_manager = Arc::new(StateManager::new(provider.clone()));
        let factory = CipherBftStateProviderFactory::new_with_defaults(Arc::new(provider), state_manager);
        let state_provider = factory.latest().unwrap();
        let retrieved = state_provider.storage(address, B256::from(slot)).unwrap();

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), value);
    }

    #[test]
    fn test_history_by_block_number() {
        let factory = create_test_factory();
        factory.block_tracker().set_latest(100, B256::repeat_byte(0x01));
        assert!(factory.history_by_block_number(100).is_ok());
        assert!(factory.history_by_block_number(200).is_err());
    }

    #[test]
    fn test_history_by_block_hash() {
        let factory = create_test_factory();
        let hash = B256::repeat_byte(0xAB);
        factory.block_tracker().set_latest(10, hash);

        // Valid hash lookup
        assert!(factory.history_by_block_hash(hash).is_ok());

        // Unknown hash should return error
        let unknown_hash = B256::repeat_byte(0xFF);
        assert!(factory.history_by_block_hash(unknown_hash).is_err());
    }

    #[test]
    fn test_state_by_block_tag() {
        let factory = create_test_factory();
        factory.block_tracker().set_latest(10, B256::repeat_byte(0x0a));
        assert!(factory.state_by_block_number_or_tag(BlockNumberOrTag::Latest).is_ok());
        assert!(factory.state_by_block_number_or_tag(BlockNumberOrTag::Pending).is_ok());
        assert!(factory.state_by_block_number_or_tag(BlockNumberOrTag::Safe).is_ok());
        assert!(factory.state_by_block_number_or_tag(BlockNumberOrTag::Finalized).is_ok());
        assert!(factory.state_by_block_number_or_tag(BlockNumberOrTag::Earliest).is_ok());
        assert!(factory.state_by_block_number_or_tag(BlockNumberOrTag::Number(5)).is_ok());
    }
}
