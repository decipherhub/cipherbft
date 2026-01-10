use async_trait::async_trait;
use alloy_primitives::{Bytes, U256};
use alloy_rpc_types::{BlockId, TransactionRequest};

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
