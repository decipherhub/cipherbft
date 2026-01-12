use alloy_primitives::B256;
use alloy_rpc_types::{Log};
use alloy_rpc_types::pubsub::PubSubSyncStatus;
use reth_primitives::SealedHeader;
use tokio::sync::broadcast;

/// Event channels used for JSON-RPC subscriptions.
#[derive(Clone)]
pub struct RpcEventChannels {
    pub new_heads: broadcast::Sender<SealedHeader>,
    pub logs: broadcast::Sender<Log>,
    pub pending_txs: broadcast::Sender<B256>,
    pub syncing: broadcast::Sender<PubSubSyncStatus>,
}

impl RpcEventChannels {
    pub fn new(buffer: usize) -> Self {
        let (new_heads, _) = broadcast::channel(buffer);
        let (logs, _) = broadcast::channel(buffer);
        let (pending_txs, _) = broadcast::channel(buffer);
        let (syncing, _) = broadcast::channel(buffer);

        Self {
            new_heads,
            logs,
            pending_txs,
            syncing,
        }
    }

    /// Emit a new head notification. Returns true if at least one listener received it.
    pub fn send_new_head(&self, header: SealedHeader) -> bool {
        self.new_heads.send(header).is_ok()
    }

    /// Emit a log notification. Returns true if at least one listener received it.
    pub fn send_log(&self, log: Log) -> bool {
        self.logs.send(log).is_ok()
    }

    /// Emit a pending transaction hash. Returns true if at least one listener received it.
    pub fn send_pending_tx(&self, hash: B256) -> bool {
        self.pending_txs.send(hash).is_ok()
    }

    /// Emit a syncing status update. Returns true if at least one listener received it.
    pub fn send_syncing(&self, status: PubSubSyncStatus) -> bool {
        self.syncing.send(status).is_ok()
    }
}
