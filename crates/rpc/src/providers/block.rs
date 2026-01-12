use async_trait::async_trait;
use alloy_primitives::B256;
use reth_primitives::{Block, Receipt, TransactionSigned};
use reth_storage_api::BlockReader;
use std::sync::Arc;

use super::{ProviderError, ProviderResult};

/// Provides block and transaction data for RPC.
#[async_trait]
pub trait BlockProvider: Send + Sync {
    async fn block_number(&self) -> ProviderResult<u64>;
    async fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<Block>>;
    async fn block_by_number(&self, number: u64) -> ProviderResult<Option<Block>>;
    async fn transaction_by_hash(&self, hash: B256) -> ProviderResult<Option<TransactionSigned>>;
    async fn receipt_by_hash(&self, hash: B256) -> ProviderResult<Option<Receipt>>;
}

/// Block provider backed by a Reth storage provider.
#[derive(Debug, Clone)]
pub struct RethBlockProvider<B> {
    backend: Arc<B>,
}

impl<B> RethBlockProvider<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl<B> BlockProvider for RethBlockProvider<B>
where
    B: BlockReader + Send + Sync,
{
    async fn block_number(&self) -> ProviderResult<u64> {
        self.backend
            .best_block_number()
            .map(|num| num as u64)
            .map_err(|err| ProviderError::Storage(err.to_string()))
    }

    async fn block_by_hash(&self, hash: B256) -> ProviderResult<Option<Block>> {
        self.backend
            .block_by_hash(hash)
            .map_err(|err| ProviderError::Storage(err.to_string()))
    }

    async fn block_by_number(&self, number: u64) -> ProviderResult<Option<Block>> {
        self.backend
            .block_by_number(number)
            .map_err(|err| ProviderError::Storage(err.to_string()))
    }

    async fn transaction_by_hash(&self, hash: B256) -> ProviderResult<Option<TransactionSigned>> {
        self.backend
            .transaction_by_hash(hash)
            .map_err(|err| ProviderError::Storage(err.to_string()))
    }

    async fn receipt_by_hash(&self, hash: B256) -> ProviderResult<Option<Receipt>> {
        self.backend
            .receipt_by_hash(hash)
            .map_err(|err| ProviderError::Storage(err.to_string()))
    }
}
