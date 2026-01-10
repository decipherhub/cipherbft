use async_trait::async_trait;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rpc_types::BlockId;

use super::ProviderResult;

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
