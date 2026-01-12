use async_trait::async_trait;
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types::{BlockId, TransactionRequest};
use std::future::Future;

use super::ProviderResult;

/// Executes eth_call/estimateGas against the execution layer.
#[async_trait]
pub trait EvmExecutor: Send + Sync {
    async fn call(&self, request: TransactionRequest, block: BlockId) -> ProviderResult<Bytes>;
    async fn estimate_gas(
        &self,
        request: TransactionRequest,
        block: BlockId,
    ) -> ProviderResult<U256>;
}

/// EVM executor backed by async call/estimate functions.
#[derive(Debug, Clone)]
pub struct EvmExecutorFn<C, G> {
    call: C,
    estimate: G,
}

impl<C, G> EvmExecutorFn<C, G> {
    pub fn new(call: C, estimate: G) -> Self {
        Self { call, estimate }
    }
}

#[async_trait]
impl<C, G, CFut, GFut> EvmExecutor for EvmExecutorFn<C, G>
where
    C: Fn(TransactionRequest, BlockId) -> CFut + Send + Sync,
    CFut: Future<Output = ProviderResult<Bytes>> + Send,
    G: Fn(TransactionRequest, BlockId) -> GFut + Send + Sync,
    GFut: Future<Output = ProviderResult<U256>> + Send,
{
    async fn call(&self, request: TransactionRequest, block: BlockId) -> ProviderResult<Bytes> {
        (self.call)(request, block).await
    }

    async fn estimate_gas(
        &self,
        request: TransactionRequest,
        block: BlockId,
    ) -> ProviderResult<U256> {
        (self.estimate)(request, block).await
    }
}
