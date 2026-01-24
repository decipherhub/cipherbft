//! Transaction pool RPC API implementation.
//!
//! This module implements the `txpool_*` JSON-RPC namespace for inspecting
//! the transaction pool state.
//!
//! # Methods
//!
//! - `txpool_status` - Returns the number of pending and queued transactions
//! - `txpool_content` - Returns all transactions in the pool grouped by sender
//! - `txpool_inspect` - Returns a text summary of transactions in the pool

use std::collections::HashMap;
use std::sync::Arc;

use alloy_primitives::Address;
use alloy_rpc_types_eth::Transaction;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::traits::MempoolApi;

/// Transaction pool status response.
///
/// Contains the counts of pending and queued transactions in the pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPoolStatus {
    /// Number of pending transactions (ready to execute)
    pub pending: u64,
    /// Number of queued transactions (waiting for nonce gaps to be filled)
    pub queued: u64,
}

/// Transaction pool content response.
///
/// Contains all transactions in the pool grouped by sender address.
/// For each sender, transactions are indexed by their nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPoolContent {
    /// Pending transactions grouped by sender address
    pub pending: HashMap<Address, HashMap<String, Transaction>>,
    /// Queued transactions grouped by sender address
    pub queued: HashMap<Address, HashMap<String, Transaction>>,
}

/// Transaction pool inspect response.
///
/// Contains a text summary of all transactions in the pool.
/// Format: "to: value wei + gas × gas_price wei"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPoolInspect {
    /// Pending transaction summaries grouped by sender address
    pub pending: HashMap<Address, HashMap<String, String>>,
    /// Queued transaction summaries grouped by sender address
    pub queued: HashMap<Address, HashMap<String, String>>,
}

/// Transaction pool RPC trait.
///
/// Defines the JSON-RPC methods for the `txpool_*` namespace.
#[rpc(server, namespace = "txpool")]
pub trait TxPoolRpc {
    /// Returns the number of transactions currently pending in the pool.
    ///
    /// # Returns
    ///
    /// A status object containing:
    /// - `pending`: Number of pending transactions
    /// - `queued`: Number of queued transactions
    #[method(name = "status")]
    async fn status(&self) -> RpcResult<TxPoolStatus>;

    /// Returns the exact details of all transactions currently pending in the pool.
    ///
    /// Transactions are grouped by sender address, then indexed by nonce.
    ///
    /// # Returns
    ///
    /// A content object containing:
    /// - `pending`: Map of sender -> (nonce -> transaction)
    /// - `queued`: Map of sender -> (nonce -> transaction)
    #[method(name = "content")]
    async fn content(&self) -> RpcResult<TxPoolContent>;

    /// Returns a textual summary of all transactions currently pending in the pool.
    ///
    /// Similar to `content` but returns a human-readable summary instead of
    /// full transaction details.
    ///
    /// # Returns
    ///
    /// An inspect object containing:
    /// - `pending`: Map of sender -> (nonce -> summary_string)
    /// - `queued`: Map of sender -> (nonce -> summary_string)
    #[method(name = "inspect")]
    async fn inspect(&self) -> RpcResult<TxPoolInspect>;
}

/// Transaction pool RPC API implementation.
///
/// This struct implements the `TxPoolRpc` trait using a `MempoolApi` backend
/// for accessing the transaction pool state.
pub struct TxPoolApi<M: MempoolApi> {
    /// Mempool backend for transaction pool operations.
    mempool: Arc<M>,
}

impl<M: MempoolApi> TxPoolApi<M> {
    /// Create a new transaction pool RPC API.
    ///
    /// # Arguments
    ///
    /// * `mempool` - Backend implementing the MempoolApi trait
    pub fn new(mempool: Arc<M>) -> Self {
        Self { mempool }
    }

    /// Format a transaction as an inspect summary string.
    ///
    /// Format: "to: value wei + gas × gas_price wei"
    fn format_inspect_summary(tx: &Transaction) -> String {
        use alloy_consensus::Transaction as ConsensusTx;

        let to = tx
            .inner
            .to()
            .map(|a| format!("{}", a))
            .unwrap_or_else(|| "contract creation".to_string());
        let value = tx.inner.value();
        let gas = tx.inner.gas_limit();
        let gas_price = tx.effective_gas_price.unwrap_or(0);

        format!("{}: {} wei + {} × {} wei", to, value, gas, gas_price)
    }
}

#[async_trait::async_trait]
impl<M: MempoolApi + Send + Sync + 'static> TxPoolRpcServer for TxPoolApi<M> {
    async fn status(&self) -> RpcResult<TxPoolStatus> {
        trace!("txpool_status");

        let (pending, queued) = self.mempool.get_pool_status().await?;

        debug!("txpool_status: {} pending, {} queued", pending, queued);

        Ok(TxPoolStatus {
            pending: pending as u64,
            queued: queued as u64,
        })
    }

    async fn content(&self) -> RpcResult<TxPoolContent> {
        trace!("txpool_content");

        // Get pending transactions grouped by sender
        let pending_by_sender = self.mempool.get_pending_content().await?;

        // Get queued transactions grouped by sender
        let queued_by_sender = self.mempool.get_queued_content().await?;

        // Convert to nonce-indexed maps
        let mut pending: HashMap<Address, HashMap<String, Transaction>> = HashMap::new();
        for (sender, txs) in pending_by_sender {
            let nonce_map: HashMap<String, Transaction> = txs
                .into_iter()
                .map(|tx| {
                    use alloy_consensus::Transaction as ConsensusTx;
                    let nonce = tx.inner.nonce().to_string();
                    (nonce, tx)
                })
                .collect();
            pending.insert(sender, nonce_map);
        }

        let mut queued: HashMap<Address, HashMap<String, Transaction>> = HashMap::new();
        for (sender, txs) in queued_by_sender {
            let nonce_map: HashMap<String, Transaction> = txs
                .into_iter()
                .map(|tx| {
                    use alloy_consensus::Transaction as ConsensusTx;
                    let nonce = tx.inner.nonce().to_string();
                    (nonce, tx)
                })
                .collect();
            queued.insert(sender, nonce_map);
        }

        debug!(
            "txpool_content: {} pending senders, {} queued senders",
            pending.len(),
            queued.len()
        );

        Ok(TxPoolContent { pending, queued })
    }

    async fn inspect(&self) -> RpcResult<TxPoolInspect> {
        trace!("txpool_inspect");

        // Get pending transactions grouped by sender
        let pending_by_sender = self.mempool.get_pending_content().await?;

        // Get queued transactions grouped by sender
        let queued_by_sender = self.mempool.get_queued_content().await?;

        // Convert to nonce-indexed summary maps
        let mut pending: HashMap<Address, HashMap<String, String>> = HashMap::new();
        for (sender, txs) in pending_by_sender {
            let nonce_map: HashMap<String, String> = txs
                .into_iter()
                .map(|tx| {
                    use alloy_consensus::Transaction as ConsensusTx;
                    let nonce = tx.inner.nonce().to_string();
                    let summary = Self::format_inspect_summary(&tx);
                    (nonce, summary)
                })
                .collect();
            pending.insert(sender, nonce_map);
        }

        let mut queued: HashMap<Address, HashMap<String, String>> = HashMap::new();
        for (sender, txs) in queued_by_sender {
            let nonce_map: HashMap<String, String> = txs
                .into_iter()
                .map(|tx| {
                    use alloy_consensus::Transaction as ConsensusTx;
                    let nonce = tx.inner.nonce().to_string();
                    let summary = Self::format_inspect_summary(&tx);
                    (nonce, summary)
                })
                .collect();
            queued.insert(sender, nonce_map);
        }

        debug!(
            "txpool_inspect: {} pending senders, {} queued senders",
            pending.len(),
            queued.len()
        );

        Ok(TxPoolInspect { pending, queued })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::StubMempoolApi;

    #[tokio::test]
    async fn test_txpool_status() {
        let mempool = Arc::new(StubMempoolApi::new());
        let api = TxPoolApi::new(mempool);

        let status = api.status().await.unwrap();
        assert_eq!(status.pending, 0);
        assert_eq!(status.queued, 0);
    }

    #[tokio::test]
    async fn test_txpool_content() {
        let mempool = Arc::new(StubMempoolApi::new());
        let api = TxPoolApi::new(mempool);

        let content = api.content().await.unwrap();
        assert!(content.pending.is_empty());
        assert!(content.queued.is_empty());
    }

    #[tokio::test]
    async fn test_txpool_inspect() {
        let mempool = Arc::new(StubMempoolApi::new());
        let api = TxPoolApi::new(mempool);

        let inspect = api.inspect().await.unwrap();
        assert!(inspect.pending.is_empty());
        assert!(inspect.queued.is_empty());
    }
}
