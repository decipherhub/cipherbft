use async_trait::async_trait;
use alloy_primitives::{Bytes, B256, U256};

use super::ProviderResult;

/// Provides mempool access for RPC submission and fee info.
#[async_trait]
pub trait TxPoolProvider: Send + Sync {
    async fn send_raw_transaction(&self, tx: Bytes) -> ProviderResult<B256>;
    async fn gas_price(&self) -> ProviderResult<U256>;
}
