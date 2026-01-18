//! WebSocket subscription manager for real-time event delivery.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use jsonrpsee::core::SubscriptionResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::PendingSubscriptionSink;
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};

use alloy_primitives::B256;
use alloy_rpc_types_eth::{Block, Filter, Log};

use crate::error::RpcError;

/// Ethereum subscription RPC trait.
///
/// Note: jsonrpsee injects `PendingSubscriptionSink` as the first argument after `&self`
/// for subscription methods. The trait definition only includes the user-provided parameters.
#[rpc(server, namespace = "eth")]
pub trait EthPubSubRpc {
    /// Creates a subscription for the given subscription type.
    ///
    /// Supported types:
    /// - "newHeads": Fires when a new block header is received
    /// - "logs": Fires when a log matching filter is included in a new block
    /// - "newPendingTransactions": Fires when a new transaction enters the mempool
    #[subscription(name = "subscribe" => "subscription", unsubscribe = "unsubscribe", item = serde_json::Value)]
    async fn subscribe(&self, kind: String, filter: Option<Filter>) -> SubscriptionResult;
}

/// Unique subscription identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u64);

impl SubscriptionId {
    /// Create a new subscription ID from a raw value.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// Subscription type.
#[derive(Debug, Clone)]
pub enum SubscriptionKind {
    /// Subscribe to new block headers.
    NewHeads,
    /// Subscribe to logs matching a filter.
    /// Boxed to reduce enum size (Filter is ~400 bytes).
    Logs(Box<Filter>),
    /// Subscribe to new pending transaction hashes.
    NewPendingTransactions,
}

/// Active subscription information.
#[derive(Debug)]
pub struct Subscription {
    /// Subscription ID.
    pub id: SubscriptionId,
    /// Subscription type.
    pub kind: SubscriptionKind,
}

/// Event types that can be broadcast to subscribers.
#[derive(Debug, Clone)]
pub enum SubscriptionEvent {
    /// New block header.
    NewHead(Box<Block>),
    /// New log entry.
    Log(Box<Log>),
    /// New pending transaction hash.
    PendingTransaction(B256),
}

/// Manages WebSocket subscriptions and broadcasts events.
pub struct SubscriptionManager {
    /// Active subscriptions by ID.
    subscriptions: DashMap<SubscriptionId, Subscription>,
    /// Counter for generating unique subscription IDs.
    next_id: AtomicU64,
    /// Broadcast channel for new block headers.
    block_tx: broadcast::Sender<Box<Block>>,
    /// Broadcast channel for logs.
    log_tx: broadcast::Sender<Box<Log>>,
    /// Broadcast channel for pending transactions.
    pending_tx_tx: broadcast::Sender<B256>,
}

impl SubscriptionManager {
    /// Create a new subscription manager with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    /// Create a new subscription manager with the given channel capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (block_tx, _) = broadcast::channel(capacity);
        let (log_tx, _) = broadcast::channel(capacity);
        let (pending_tx_tx, _) = broadcast::channel(capacity);

        Self {
            subscriptions: DashMap::new(),
            next_id: AtomicU64::new(1),
            block_tx,
            log_tx,
            pending_tx_tx,
        }
    }

    /// Create a new subscription.
    pub fn subscribe(&self, kind: SubscriptionKind) -> SubscriptionId {
        let id = SubscriptionId(self.next_id.fetch_add(1, Ordering::SeqCst));
        let subscription = Subscription {
            id,
            kind: kind.clone(),
        };
        self.subscriptions.insert(id, subscription);
        id
    }

    /// Remove a subscription.
    pub fn unsubscribe(&self, id: SubscriptionId) -> bool {
        self.subscriptions.remove(&id).is_some()
    }

    /// Get the number of active subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Broadcast a new block header to all newHeads subscribers.
    pub fn broadcast_block(&self, block: Block) {
        let _ = self.block_tx.send(Box::new(block));
    }

    /// Broadcast a log to matching log subscribers.
    pub fn broadcast_log(&self, log: Log) {
        let _ = self.log_tx.send(Box::new(log));
    }

    /// Broadcast a pending transaction hash.
    pub fn broadcast_pending_transaction(&self, tx_hash: B256) {
        let _ = self.pending_tx_tx.send(tx_hash);
    }

    /// Subscribe to new block headers channel.
    pub fn subscribe_blocks(&self) -> broadcast::Receiver<Box<Block>> {
        self.block_tx.subscribe()
    }

    /// Subscribe to logs channel.
    pub fn subscribe_logs(&self) -> broadcast::Receiver<Box<Log>> {
        self.log_tx.subscribe()
    }

    /// Subscribe to pending transactions channel.
    pub fn subscribe_pending_txs(&self) -> broadcast::Receiver<B256> {
        self.pending_tx_tx.subscribe()
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Ethereum pub/sub RPC handler.
pub struct EthPubSubApi {
    /// Subscription manager.
    manager: Arc<SubscriptionManager>,
}

impl EthPubSubApi {
    /// Create a new EthPubSubApi instance.
    pub fn new(manager: Arc<SubscriptionManager>) -> Self {
        Self { manager }
    }
}

#[async_trait::async_trait]
impl EthPubSubRpcServer for EthPubSubApi {
    /// Implementation of eth_subscribe.
    /// The PendingSubscriptionSink is injected by jsonrpsee as the second parameter.
    async fn subscribe(
        &self,
        pending: PendingSubscriptionSink,
        kind: String,
        filter: Option<Filter>,
    ) -> SubscriptionResult {
        // Parse subscription kind
        let sub_kind = match kind.as_str() {
            "newHeads" => SubscriptionKind::NewHeads,
            "logs" => {
                let f = filter.unwrap_or_default();
                SubscriptionKind::Logs(Box::new(f))
            }
            "newPendingTransactions" => SubscriptionKind::NewPendingTransactions,
            _ => {
                let err: ErrorObjectOwned = RpcError::InvalidParams(format!(
                    "Unknown subscription type: {}. Supported: newHeads, logs, newPendingTransactions",
                    kind
                ))
                .into();
                pending.reject(err).await;
                return Ok(());
            }
        };

        debug!("New subscription request: {:?}", sub_kind);

        // Accept the subscription
        let sink = pending.accept().await?;
        let sub_id = self.manager.subscribe(sub_kind.clone());
        trace!("Subscription {} created", sub_id);

        // Spawn task to handle events based on subscription type
        match sub_kind {
            SubscriptionKind::NewHeads => {
                let mut rx = self.manager.subscribe_blocks();
                let manager = Arc::clone(&self.manager);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = sink.closed() => {
                                trace!("NewHeads subscription {} closed by client", sub_id);
                                manager.unsubscribe(sub_id);
                                break;
                            }
                            result = rx.recv() => {
                                match result {
                                    Ok(block) => {
                                        let msg = serde_json::to_value(&*block).unwrap_or_default();
                                        if sink.send(jsonrpsee::SubscriptionMessage::from_json(&msg).unwrap()).await.is_err() {
                                            trace!("Failed to send to subscription {}, closing", sub_id);
                                            manager.unsubscribe(sub_id);
                                            break;
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        warn!("Subscription {} lagged by {} messages", sub_id, n);
                                    }
                                    Err(broadcast::error::RecvError::Closed) => {
                                        trace!("Block broadcast channel closed for subscription {}", sub_id);
                                        manager.unsubscribe(sub_id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
            SubscriptionKind::Logs(log_filter) => {
                let mut rx = self.manager.subscribe_logs();
                let manager = Arc::clone(&self.manager);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = sink.closed() => {
                                trace!("Logs subscription {} closed by client", sub_id);
                                manager.unsubscribe(sub_id);
                                break;
                            }
                            result = rx.recv() => {
                                match result {
                                    Ok(log) => {
                                        // Check if log matches the filter
                                        if matches_filter(&log, &log_filter) {
                                            let msg = serde_json::to_value(&*log).unwrap_or_default();
                                            if sink.send(jsonrpsee::SubscriptionMessage::from_json(&msg).unwrap()).await.is_err() {
                                                trace!("Failed to send to subscription {}, closing", sub_id);
                                                manager.unsubscribe(sub_id);
                                                break;
                                            }
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        warn!("Subscription {} lagged by {} messages", sub_id, n);
                                    }
                                    Err(broadcast::error::RecvError::Closed) => {
                                        trace!("Log broadcast channel closed for subscription {}", sub_id);
                                        manager.unsubscribe(sub_id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
            SubscriptionKind::NewPendingTransactions => {
                let mut rx = self.manager.subscribe_pending_txs();
                let manager = Arc::clone(&self.manager);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = sink.closed() => {
                                trace!("PendingTxs subscription {} closed by client", sub_id);
                                manager.unsubscribe(sub_id);
                                break;
                            }
                            result = rx.recv() => {
                                match result {
                                    Ok(tx_hash) => {
                                        let msg = serde_json::to_value(tx_hash).unwrap_or_default();
                                        if sink.send(jsonrpsee::SubscriptionMessage::from_json(&msg).unwrap()).await.is_err() {
                                            trace!("Failed to send to subscription {}, closing", sub_id);
                                            manager.unsubscribe(sub_id);
                                            break;
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        warn!("Subscription {} lagged by {} messages", sub_id, n);
                                    }
                                    Err(broadcast::error::RecvError::Closed) => {
                                        trace!("PendingTx broadcast channel closed for subscription {}", sub_id);
                                        manager.unsubscribe(sub_id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }

        Ok(())
    }
}

/// Check if a log matches the given filter.
fn matches_filter(log: &Log, filter: &Filter) -> bool {
    // Check address filter (FilterSet is not Option, use is_empty/matches)
    if !filter.address.is_empty() && !filter.address.matches(&log.address()) {
        return false;
    }

    // Check topics filter
    // filter.topics is [FilterSet<B256>; 4] for topic0-3
    for (i, topic_filter) in filter.topics.iter().enumerate() {
        if !topic_filter.is_empty() {
            let log_topic = log.topics().get(i);
            match log_topic {
                Some(lt) => {
                    if !topic_filter.matches(lt) {
                        return false;
                    }
                }
                None => return false, // Filter expects topic but log doesn't have it
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_id() {
        let manager = SubscriptionManager::default();
        let id1 = manager.subscribe(SubscriptionKind::NewHeads);
        let id2 = manager.subscribe(SubscriptionKind::NewHeads);
        assert_ne!(id1, id2);
        assert_eq!(manager.subscription_count(), 2);
    }

    #[test]
    fn test_unsubscribe() {
        let manager = SubscriptionManager::default();
        let id = manager.subscribe(SubscriptionKind::NewHeads);
        assert_eq!(manager.subscription_count(), 1);
        assert!(manager.unsubscribe(id));
        assert_eq!(manager.subscription_count(), 0);
        assert!(!manager.unsubscribe(id)); // Already removed
    }
}
