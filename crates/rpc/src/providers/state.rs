use async_trait::async_trait;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rpc_types::BlockId;
use reth_storage_api::StateProviderFactory;
use std::sync::Arc;

use super::{ProviderError, ProviderResult};

/// Provides account/state queries for RPC.
#[async_trait]
pub trait StateProvider: Send + Sync {
    async fn balance(&self, address: Address, block: BlockId) -> ProviderResult<U256>;
    async fn code(&self, address: Address, block: BlockId) -> ProviderResult<Bytes>;
    async fn storage_at(
        &self,
        address: Address,
        slot: B256,
        block: BlockId,
    ) -> ProviderResult<B256>;
    async fn transaction_count(&self, address: Address, block: BlockId) -> ProviderResult<u64>;
}

/// State provider backed by a Reth `StateProviderFactory`.
#[derive(Debug, Clone)]
pub struct RethStateProvider<F> {
    factory: Arc<F>,
}

impl<F> RethStateProvider<F> {
    pub fn new(factory: Arc<F>) -> Self {
        Self { factory }
    }
}

#[async_trait]
impl<F> StateProvider for RethStateProvider<F>
where
    F: StateProviderFactory + Send + Sync,
{
    async fn balance(&self, address: Address, block: BlockId) -> ProviderResult<U256> {
        let state = self
            .factory
            .state_by_block_id(block)
            .map_err(|err| ProviderError::Storage(err.to_string()))?;
        let balance = state
            .account_balance(address)
            .map_err(|err| ProviderError::Storage(err.to_string()))?
            .unwrap_or_default();
        Ok(balance)
    }

    async fn code(&self, address: Address, block: BlockId) -> ProviderResult<Bytes> {
        let state = self
            .factory
            .state_by_block_id(block)
            .map_err(|err| ProviderError::Storage(err.to_string()))?;
        let code = state
            .account_code(address)
            .map_err(|err| ProviderError::Storage(err.to_string()))?
            .map(|bytecode| bytecode.0.original_bytes())
            .unwrap_or_default();
        Ok(code)
    }

    async fn storage_at(
        &self,
        address: Address,
        slot: B256,
        block: BlockId,
    ) -> ProviderResult<B256> {
        let state = self
            .factory
            .state_by_block_id(block)
            .map_err(|err| ProviderError::Storage(err.to_string()))?;
        let value = state
            .storage(address, slot)
            .map_err(|err| ProviderError::Storage(err.to_string()))?
            .unwrap_or_default();
        Ok(B256::from(value.to_be_bytes()))
    }

    async fn transaction_count(&self, address: Address, block: BlockId) -> ProviderResult<u64> {
        let state = self
            .factory
            .state_by_block_id(block)
            .map_err(|err| ProviderError::Storage(err.to_string()))?;
        let nonce = state
            .account_nonce(address)
            .map_err(|err| ProviderError::Storage(err.to_string()))?
            .unwrap_or_default();
        Ok(nonce)
    }
}
