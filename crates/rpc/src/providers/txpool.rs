use async_trait::async_trait;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Bytes, B256, U256};
use mempool::CipherBftPool;
use mempool::pool::PoolStats;
use reth_primitives::{
    PooledTransactionsElement, PooledTransactionsElementEcRecovered, TransactionSignedEcRecovered,
    TransactionSigned,
};
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use std::sync::Arc;

use super::{ProviderError, ProviderResult};

/// Provides mempool access for RPC submission and fee info.
#[async_trait]
pub trait TxPoolProvider: Send + Sync {
    async fn send_raw_transaction(&self, tx: Bytes) -> ProviderResult<B256>;
    async fn gas_price(&self) -> ProviderResult<U256>;
    async fn pending_transactions(&self) -> ProviderResult<Vec<TransactionSigned>>;
    async fn queued_transactions(&self) -> ProviderResult<Vec<TransactionSigned>>;
    async fn txpool_status(&self) -> ProviderResult<PoolStats>;
}

/// TxPool provider backed by the CipherBFT mempool wrapper.
#[derive(Clone)]
pub struct MempoolTxPoolProvider<P: TransactionPool> {
    pool: Arc<CipherBftPool<P>>,
}

impl<P: TransactionPool> MempoolTxPoolProvider<P> {
    pub fn new(pool: Arc<CipherBftPool<P>>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl<P> TxPoolProvider for MempoolTxPoolProvider<P>
where
    P: TransactionPool,
    P::Transaction: PoolTransaction + TryFrom<TransactionSignedEcRecovered>,
    <P::Transaction as PoolTransaction>::Consensus: Into<TransactionSignedEcRecovered>,
    <P::Transaction as PoolTransaction>::Pooled: From<PooledTransactionsElementEcRecovered>,
    <P::Transaction as TryFrom<TransactionSignedEcRecovered>>::Error: std::fmt::Display,
{
    async fn send_raw_transaction(&self, tx: Bytes) -> ProviderResult<B256> {
        let mut slice = tx.as_ref();
        let pooled = PooledTransactionsElement::decode_2718(&mut slice)
            .map_err(|err| ProviderError::Mempool(err.to_string()))?;
        let hash = *pooled.hash();

        self.pool
            .add_transaction(TransactionOrigin::External, pooled)
            .await
            .map_err(|err| ProviderError::Mempool(err.to_string()))?;

        Ok(hash)
    }

    async fn gas_price(&self) -> ProviderResult<U256> {
        let mut max_fee = 0u128;
        for tx in self.pool.adapter().pending_transactions() {
            max_fee = max_fee.max(tx.max_fee_per_gas());
        }
        Ok(U256::from(max_fee))
    }

    async fn pending_transactions(&self) -> ProviderResult<Vec<TransactionSigned>> {
        Ok(self.pool.adapter().pending_transactions())
    }

    async fn queued_transactions(&self) -> ProviderResult<Vec<TransactionSigned>> {
        Ok(self.pool.adapter().queued_transactions())
    }

    async fn txpool_status(&self) -> ProviderResult<PoolStats> {
        Ok(self.pool.adapter().stats())
    }
}
