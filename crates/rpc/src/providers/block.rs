use async_trait::async_trait;
use alloy_primitives::B256;
use reth_primitives::{Block, Receipt, TransactionSigned};

use super::ProviderResult;

/// Provides block and transaction data for RPC.
#[async_trait]
pub trait BlockProvider: Send + Sync {
    async fn block_number(&self) -> ProviderResult<u64>;
    async fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<Block>>;
    async fn block_by_number(&self, number: u64) -> ProviderResult<Option<Block>>;
    async fn transaction_by_hash(&self, hash: B256) -> ProviderResult<Option<TransactionSigned>>;
    async fn receipt_by_hash(&self, hash: B256) -> ProviderResult<Option<Receipt>>;
}
